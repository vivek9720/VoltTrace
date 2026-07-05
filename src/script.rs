use crate::cursor::ByteCursor;
use crate::error::Result;

#[derive(Debug, Clone, Copy)]
pub enum Value {
    Nil,
    Bool(bool),
    I32(i32),
    U32(u32),
    Timestamp(u64),
}

#[derive(Debug, Clone, Copy)]
pub enum Instruction {
    LoadI32 { dst: u8, value: i32 },
    LoadU32 { dst: u8, value: u32 },
    Add { dst: u8, a: u8, b: u8 },
    Xor { dst: u8, a: u8, b: u8 },
    CompareGt { dst: u8, a: u8, b: u8 },
    JumpIf { reg: u8, offset: i8 },
    PinWindow { start: u8, len: u8 },
    Grow { count: u16 },
    Resume { dst: u8, salt: u8 },
    Emit { reg: u8 },
    Halt,
}

#[derive(Debug, Clone)]
pub struct Program {
    pub script_id: u32,
    pub register_count: u16,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub script_id: u32,
    pub emitted: Vec<u32>,
    pub steps: u32,
    pub checksum: u32,
}

#[derive(Clone, Copy)]
struct RegisterWindow {
    ptr: *mut Value,
    len: usize,
    generation: u32,
}

pub fn compile_and_run(data: &[u8]) -> Result<ExecutionReport> {
    let program = parse_program(data)?;
    Vm::new(program.register_count).execute(&program)
}

pub fn parse_program(data: &[u8]) -> Result<Program> {
    let mut cur = ByteCursor::new(data, "script program");
    let script_id = if cur.remaining() >= 4 { cur.read_u32()? } else { 0 };
    let register_count = if cur.remaining() >= 2 { cur.read_u16()?.clamp(4, 256) } else { 16 };
    let mut instructions = Vec::new();
    while cur.remaining() > 0 && instructions.len() < 4096 {
        let opcode = cur.read_u8()?;
        let ins = match opcode {
            0x01 => Instruction::LoadI32 { dst: cur.read_u8()?, value: cur.read_i32()? },
            0x02 => Instruction::LoadU32 { dst: cur.read_u8()?, value: cur.read_u32()? },
            0x03 => Instruction::Add { dst: cur.read_u8()?, a: cur.read_u8()?, b: cur.read_u8()? },
            0x04 => Instruction::Xor { dst: cur.read_u8()?, a: cur.read_u8()?, b: cur.read_u8()? },
            0x05 => Instruction::CompareGt { dst: cur.read_u8()?, a: cur.read_u8()?, b: cur.read_u8()? },
            0x06 => Instruction::JumpIf { reg: cur.read_u8()?, offset: cur.read_i8()? },
            0x07 => Instruction::PinWindow { start: cur.read_u8()?, len: cur.read_u8()? },
            0x08 => Instruction::Grow { count: cur.read_u16()? },
            0x09 => Instruction::Resume { dst: cur.read_u8()?, salt: cur.read_u8()? },
            0x0a => Instruction::Emit { reg: cur.read_u8()? },
            0xff => Instruction::Halt,
            _ => Instruction::Xor { dst: opcode & 15, a: opcode.rotate_left(1) & 15, b: opcode.rotate_right(1) & 15 },
        };
        instructions.push(ins);
    }
    if instructions.is_empty() {
        instructions.push(Instruction::Halt);
    }
    Ok(Program { script_id, register_count, instructions })
}

struct Vm {
    registers: Vec<Value>,
    window: Option<RegisterWindow>,
    generation: u32,
    emitted: Vec<u32>,
}

impl Vm {
    fn new(register_count: u16) -> Self {
        let mut registers = Vec::with_capacity(register_count as usize);
        registers.resize(register_count as usize, Value::Nil);
        Self { registers, window: None, generation: 1, emitted: Vec::new() }
    }

    fn execute(mut self, program: &Program) -> Result<ExecutionReport> {
        let mut ip: isize = 0;
        let mut steps = 0u32;
        while ip >= 0 && (ip as usize) < program.instructions.len() && steps < 10_000 {
            let ins = program.instructions[ip as usize];
            steps = steps.wrapping_add(1);
            match ins {
                Instruction::LoadI32 { dst, value } => self.set(dst, Value::I32(value)),
                Instruction::LoadU32 { dst, value } => self.set(dst, Value::U32(value)),
                Instruction::Add { dst, a, b } => {
                    let v = self.get_i32(a).wrapping_add(self.get_i32(b));
                    self.set(dst, Value::I32(v));
                }
                Instruction::Xor { dst, a, b } => {
                    let v = self.get_u32(a) ^ self.get_u32(b);
                    self.set(dst, Value::U32(v));
                }
                Instruction::CompareGt { dst, a, b } => {
                    self.set(dst, Value::Bool(self.get_i32(a) > self.get_i32(b)));
                }
                Instruction::JumpIf { reg, offset } => {
                    if self.truthy(reg) {
                        ip += offset as isize;
                        continue;
                    }
                }
                Instruction::PinWindow { start, len } => self.pin_window(start as usize, len as usize),
                Instruction::Grow { count } => self.grow(count as usize),
                Instruction::Resume { dst, salt } => self.resume_window(dst as usize, salt),
                Instruction::Emit { reg } => self.emitted.push(self.get_u32(reg)),
                Instruction::Halt => break,
            }
            ip += 1;
        }
        let checksum = self.emitted.iter().fold(program.script_id, |acc, v| acc.rotate_left(3) ^ *v);
        Ok(ExecutionReport { script_id: program.script_id, emitted: self.emitted, steps, checksum })
    }

    fn set(&mut self, reg: u8, value: Value) {
        if self.registers.is_empty() {
            self.registers.push(Value::Nil);
        }
        let idx = reg as usize % self.registers.len();
        self.registers[idx] = value;
    }

    fn get(&self, reg: u8) -> Value {
        if self.registers.is_empty() {
            return Value::Nil;
        }
        self.registers.get(reg as usize % self.registers.len()).copied().unwrap_or(Value::Nil)
    }

    fn get_i32(&self, reg: u8) -> i32 {
        match self.get(reg) {
            Value::I32(v) => v,
            Value::U32(v) => v as i32,
            Value::Bool(v) => if v { 1 } else { 0 },
            Value::Timestamp(v) => v as i32,
            Value::Nil => 0,
        }
    }

    fn get_u32(&self, reg: u8) -> u32 {
        match self.get(reg) {
            Value::I32(v) => v as u32,
            Value::U32(v) => v,
            Value::Bool(v) => if v { 1 } else { 0 },
            Value::Timestamp(v) => v as u32,
            Value::Nil => 0,
        }
    }

    fn truthy(&self, reg: u8) -> bool {
        match self.get(reg) {
            Value::Bool(v) => v,
            Value::I32(v) => v != 0,
            Value::U32(v) => v != 0,
            Value::Timestamp(v) => v != 0,
            Value::Nil => false,
        }
    }

    fn pin_window(&mut self, start: usize, len: usize) {
        if self.registers.is_empty() || len == 0 {
            return;
        }
        let start = start.min(self.registers.len() - 1);
        let len = len.min(self.registers.len() - start);
        let ptr = unsafe { self.registers.as_mut_ptr().add(start) };
        self.window = Some(RegisterWindow { ptr, len, generation: self.generation });
    }

    fn grow(&mut self, count: usize) {
        let target = self.registers.len().saturating_add(count.min(4096));
        while self.registers.len() < target {
            let value = Value::Timestamp((self.registers.len() as u64).wrapping_mul(977));
            self.registers.push(value);
        }
        if count & 1 != 0 {
            self.registers.shrink_to_fit();
        }
        self.generation = self.generation.wrapping_add(1);
    }

    fn resume_window(&mut self, dst: usize, salt: u8) {
        let Some(window) = self.window else { return; };
        if window.len == 0 {
            return;
        }
        let mut acc = salt as u32 ^ window.generation;
        unsafe {
            for i in 0..window.len.min(64) {
                let v = *window.ptr.add(i);
                acc = acc.rotate_left(5) ^ value_bits(v).wrapping_add(i as u32);
            }
            if !self.registers.is_empty() {
                let idx = dst % self.registers.len();
                self.registers[idx] = Value::U32(acc);
            }
        }
    }
}

fn value_bits(v: Value) -> u32 {
    match v {
        Value::Nil => 0,
        Value::Bool(b) => if b { 1 } else { 0 },
        Value::I32(x) => x as u32,
        Value::U32(x) => x,
        Value::Timestamp(x) => (x as u32) ^ ((x >> 32) as u32),
    }
}
