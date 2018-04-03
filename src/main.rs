extern crate keystone;
extern crate tabwriter;
#[macro_use] extern crate clap;
#[macro_use] extern crate failure;

use std::io::{Read, Write, BufRead};

static APPLICATION_NAME: &'static str = "rkasm";
static APPLICATION_VERSION: &'static str = "0.1.0";
static APPLICATION_AUTHOR: &'static str = "TA Thanh Dinh <tathanhdinh@gmail.com>";
static APPLICATION_ABOUT: &'static str = "A simpler x86 assembler based on keystone";

static ARGUMENT_ASM: &'static str = "x86 assembly";
static ARGUMENT_BASE: &'static str = "base address";
static ARGUMENT_MODE: &'static str = "assembling mode";
static ARGUMENT_FILE: &'static str = "input x86 assembly file";

fn main() {
    let matches = clap::App::new(APPLICATION_NAME)
        .version(APPLICATION_VERSION)
        .author(APPLICATION_AUTHOR)
        .about(APPLICATION_ABOUT)
        .arg(clap::Arg::with_name(ARGUMENT_ASM)
             .required(true)
             .index(1))
        .arg(clap::Arg::with_name(ARGUMENT_BASE)
             .short("b")
             .long("base")
             .takes_value(true)
             .default_value("0"))
        .arg(clap::Arg::with_name(ARGUMENT_MODE)
             .short("m")
             .long("mode")
             .takes_value(true)
             .default_value("x64")
             .possible_values(&["x64", "x32"]))
        .get_matches();

    let asm_mode = if matches.is_present(ARGUMENT_MODE) {
        match matches.value_of(ARGUMENT_MODE).unwrap() {
            "x32" => {
                keystone::gen::KS_MODE_32
            },
            "x64" => {
                keystone::gen::KS_MODE_64
            },
            _ => {
                unreachable!();
            }
        }
    }
    else {
        keystone::gen::KS_MODE_64
    };

    let base_address = if matches.is_present(ARGUMENT_BASE) {
        value_t!(matches, ARGUMENT_BASE, u64).unwrap_or(0x0)
    }
    else {
        0x0
    };

    let engine = keystone::Keystone::new(keystone::gen::KS_ARCH_X86, asm_mode)
        .expect("could not initialize Keystone engine");
    engine.option(keystone::gen::KS_OPT_SYNTAX, keystone::gen::KS_OPT_SYNTAX_NASM)
        .expect("could not set option to NASM syntax");

    let asm_code = matches.value_of(ARGUMENT_ASM).unwrap(); // should not panic since required
    let asm_code: Vec<_> = asm_code.split(';').collect();
    let asm_code: Vec<_> = asm_code.into_iter().map(|ins| ins.trim()).collect();

    let mut assembled_strings: Vec<_> = Vec::new();
    let mut assembled_ins_string;
    let mut ins_base_address = base_address;
    for ins in asm_code {
        let assembling_result = 
            if let Ok(assembled_ins) = engine.asm(&ins, ins_base_address) {
                let opcode_len = assembled_ins.encoding.len();
                let opcode_strs: Vec<_> = assembled_ins.encoding
                    .into_iter()
                    .map(|opc| format!("{:02x}", opc))
                    .collect();
                let opcode_string = opcode_strs.join(" ");
                
                assembled_ins_string = format!("0x{:x}\t{}\t{}", ins_base_address, &opcode_string, ins);
                // asm_results.push(asm_result);
                // Ok(format!("0x{:016x}\t{}\t{}", ins_base_address, &opcode_string, ins))
                ins_base_address += opcode_len as u64;
                Some(())
            }
            else {
                assembled_ins_string = format!("0x{:x}\t{}\t{}", ins_base_address, "error", ins);
                // asm_results.push(asm_result);
                // break;
                // Err(format!("0x{:016x}\t{}\t{}", ins_base_address, "error", ins))
                // Err(())
                None
            };

        assembled_strings.push(assembled_ins_string);
        if assembling_result.is_none() {
            break;
        }
    }
    let asm_results = assembled_strings.join("\r\n");
    // println!("{}", asm_results.len());

    // let mut tw = tabwriter::TabWriter::new(Vec::new()).padding(2);
    let mut tw = tabwriter::TabWriter::new(std::io::stdout()).padding(4);
    // write!(&mut tw, &asm_results);
    writeln!(&mut tw, "{}", asm_results).unwrap();
    tw.flush().unwrap();
}

fn run() -> Result<(), failure::Error> {
    let matches = clap::App::new(APPLICATION_NAME)
        .version(APPLICATION_VERSION)
        .author(APPLICATION_AUTHOR)
        .about(APPLICATION_ABOUT)
        .arg(clap::Arg::with_name(ARGUMENT_ASM)
             .required_unless(ARGUMENT_FILE)
             .index(1))
        .arg(clap::Arg::with_name(ARGUMENT_FILE)
             .short("f")
             .long("file")
             .takes_value(true)
             .conflicts_with(ARGUMENT_ASM))
        .arg(clap::Arg::with_name(ARGUMENT_BASE)
             .short("b")
             .long("base")
             .takes_value(true)
             .default_value("0"))
        .arg(clap::Arg::with_name(ARGUMENT_MODE)
             .short("m")
             .long("mode")
             .takes_value(true)
             .default_value("x64")
             .possible_values(&["x64", "x32"]))
        .get_matches();

    let asm_mode = if matches.is_present(ARGUMENT_MODE) {
        match matches.value_of(ARGUMENT_MODE).unwrap() {
            "x32" => {
                keystone::gen::KS_MODE_32
            },
            "x64" => {
                keystone::gen::KS_MODE_64
            },
            _ => {
                unreachable!();
            }
        }
    }
    else {
        keystone::gen::KS_MODE_64
    };

    let base_address = if matches.is_present(ARGUMENT_BASE) {
        value_t!(matches, ARGUMENT_BASE, u64).unwrap_or(0x0)
    }
    else {
        0x0
    };

    let engine = keystone::Keystone::new(keystone::gen::KS_ARCH_X86, asm_mode)
        .expect("could not initialize Keystone engine");
    engine.option(keystone::gen::KS_OPT_SYNTAX, keystone::gen::KS_OPT_SYNTAX_NASM)
        .expect("could not set option to NASM syntax");

    // let mut asm_code: Vec<&str> = vec![];
    let input_file_reader;
    let mut asm_code = vec![];
    if matches.is_present(ARGUMENT_FILE) {
        let input_file = std::fs::File::open(matches.value_of(ARGUMENT_FILE).unwrap())?;
        input_file_reader = std::io::BufReader::new(input_file);
        // input_file.lines().into_iter().map(|line| line?.trim()).collect();;
        // for line in input_file_reader.lines() {
        //     asm_code.push(line?.trim());
        // }
        let input_asm: Vec<_> = 
    }
    else {
        let input_asm = matches.value_of(ARGUMENT_ASM).unwrap(); // should not panic since required
        let input_asm: Vec<_> = input_asm.split(';').collect();
        asm_code = input_asm.into_iter().map(|ins| ins.trim()).collect();
    }

    let mut assembled_strings: Vec<_> = Vec::new();
    let mut assembled_ins_string;
    let mut ins_base_address = base_address;
    for ref ins in asm_code {
        let assembling_result = 
            if let Ok(assembled_ins) = engine.asm(&ins, ins_base_address) {
                let opcode_len = assembled_ins.encoding.len();
                let opcode_strs: Vec<_> = assembled_ins.encoding
                    .into_iter()
                    .map(|opc| format!("{:02x}", opc))
                    .collect();
                let opcode_string = opcode_strs.join(" ");
                
                assembled_ins_string = format!("0x{:x}\t{}\t{}", ins_base_address, &opcode_string, ins);
                // asm_results.push(asm_result);
                // Ok(format!("0x{:016x}\t{}\t{}", ins_base_address, &opcode_string, ins))
                ins_base_address += opcode_len as u64;
                Some(())
            }
            else {
                assembled_ins_string = format!("0x{:x}\t{}\t{}", ins_base_address, "error", ins);
                // asm_results.push(asm_result);
                // break;
                // Err(format!("0x{:016x}\t{}\t{}", ins_base_address, "error", ins))
                // Err(())
                None
            };

        assembled_strings.push(assembled_ins_string);
        if assembling_result.is_none() {
            break;
        }
    }
    let asm_results = assembled_strings.join("\r\n");
    // println!("{}", asm_results.len());

    // let mut tw = tabwriter::TabWriter::new(Vec::new()).padding(2);
    let mut tw = tabwriter::TabWriter::new(std::io::stdout()).padding(4);
    // write!(&mut tw, &asm_results);
    writeln!(&mut tw, "{}", asm_results)?;
    tw.flush()?;

    Ok(())
}