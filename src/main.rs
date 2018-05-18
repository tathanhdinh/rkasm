// #![feature(fs_read_write)]

extern crate keystone;
extern crate tabwriter;
#[cfg(target_os = "linux")] extern crate syntect;
#[cfg(target_os = "linux")] extern crate pager;
#[macro_use] extern crate clap;
#[macro_use] extern crate failure;

use std::io::{Write, BufRead};

static APPLICATION_NAME: &'static str = "rkasm";
static APPLICATION_VERSION: &'static str = "0.1.0";
static APPLICATION_AUTHOR: &'static str = "TA Thanh Dinh <tathanhdinh@gmail.com>";
static APPLICATION_ABOUT: &'static str = "A simpler x86 assembler based on keystone";

static ARGUMENT_ASM: &'static str = "x86 assembly";
static ARGUMENT_BASE_ADDRESS: &'static str = "base address";
static ARGUMENT_MODE: &'static str = "assembling mode";
static ARGUMENT_FILE: &'static str = "input x86 assembly file";
static ARGUMENT_OUTPUT_FILE: &'static str = "output binary file";
static ARGUMENT_VERBOSE: &'static str = "show assembly code";

fn main() {
    // pager::Pager::with_pager("less -R").setup();

    // if let Err(err) = run() {
    //     println!("{}", err);
    // }

    match run() {
        Ok(()) => {},
        Err(ref err) => {
            if let Some(ref _err) = err.downcast_ref::<std::io::Error>() {
                std::process::exit(0);
            }
            else {
                println!("Error: {}", err);
            }
        }
    }
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
        .arg(clap::Arg::with_name(ARGUMENT_OUTPUT_FILE)
             .short("o")
             .long("out")
             .takes_value(true))
        .arg(clap::Arg::with_name(ARGUMENT_BASE_ADDRESS)
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
        .arg(clap::Arg::with_name(ARGUMENT_VERBOSE)
             .short("v")
             .long("verbose"))
        .get_matches();

    let verbose_mode = matches.is_present(ARGUMENT_VERBOSE);

    #[cfg(target_os = "linux")]
    {
        if verbose_mode {
            pager::Pager::with_pager("less -R -X").setup();
        }
    }

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

    let base_address = if matches.is_present(ARGUMENT_BASE_ADDRESS) {
        value_t!(matches, ARGUMENT_BASE_ADDRESS, u64).unwrap_or(0x0)
    }
    else {
        0x0
    };

    let engine = keystone::Keystone::new(keystone::gen::KS_ARCH_X86, asm_mode)
        .expect("could not initialize Keystone engine");
    engine.option(keystone::gen::KS_OPT_SYNTAX, keystone::gen::KS_OPT_SYNTAX_NASM)
        .expect("could not set option to NASM syntax");

    // let mut output_file = std::io::BufWriter::new(Box::new(std::io::stdout()) as Box<std::io::Write>);
    // let mut output_to_file = false;
    // if matches.is_present(ARGUMENT_OUTPUT_FILE) {
    //     output_to_file = true;
    //     // output_file = matches.value_of(ARGUMENT_OUTPUT_FILE).unwrap();
    //     let file = std::fs::File::create(matches.value_of(ARGUMENT_OUTPUT_FILE).unwrap())?;
    //     output_file = std::io::BufWriter::new(Box::new(file) as Box<std::io::Write>)
    // };

    let (mut output_file, output_to_file) = 
        if matches.is_present(ARGUMENT_OUTPUT_FILE) {
            let file = std::fs::File::create(matches.value_of(ARGUMENT_OUTPUT_FILE).unwrap())?;
            (std::io::BufWriter::new(Box::new(file) as Box<std::io::Write>), true)
        }
        else {
            (std::io::BufWriter::new(Box::new(std::io::stdout()) as Box<std::io::Write>), false)
        };

    let lines;
    let asm_code = 
        if matches.is_present(ARGUMENT_FILE) {
            let input_file = std::fs::File::open(matches.value_of(ARGUMENT_FILE).unwrap())?;
            let input_file = std::io::BufReader::new(input_file);
            // input_file.lines().into_iter().map(|line| line?.trim()).collect();;
            // for line in input_file_reader.lines() {
            //     asm_code.push(line?.trim());
            // }
            // let input_asm: Vec<_> = 
            lines = input_file.lines().collect::<Result<Vec<String>, _>>()?;
            lines.iter()
                .map(|s| s.as_str().trim())
                .filter(|s| !s.starts_with(';') && !s.is_empty())
                .collect::<Vec<&str>>()
            // asm_code = lines.iter().map(|s| s.trim()).collect::<Vec<&str>>();
        }
        else {
            let input_asm = matches.value_of(ARGUMENT_ASM).unwrap(); // should not panic since required
            let input_asm: Vec<_> = input_asm.split(';').collect();
            input_asm.into_iter().map(|ins| ins.trim()).collect()
        };

    let mut assembled_strings: Vec<_> = Vec::new();
    // let mut assembled_ins_string = String::from("");
    //  = &String::new();
    let mut ins_base_address = base_address;
    for ins in asm_code {
        let assembling_result = 
            if let Ok(assembled_ins) = engine.asm(&ins, ins_base_address) {
                let opcode_len = assembled_ins.encoding.len();
                let opcode_strs: Vec<_> = assembled_ins.encoding
                    .iter()
                    .map(|opc| format!("{:02x}", opc))
                    .collect();
                let opcode_string = opcode_strs.join(" ");
                
                // if verbose_mode {
                //     assembled_ins_string = format!("0x{:x}\t{}\t{}", ins_base_address, &opcode_string, ins);
                // }
                // else {
                //     assembled_ins_string = String::from("");
                // }
                
                // asm_results.push(asm_result);
                // Ok(format!("0x{:016x}\t{}\t{}", ins_base_address, &opcode_string, ins))
                ins_base_address += opcode_len as u64;

                if output_to_file {
                    // std::fs::write(output_file, &assembled_ins.encoding)?;
                    output_file.write_all(&assembled_ins.encoding)?;
                }

                Ok(format!("0x{:x}\t{}\t{}", ins_base_address, &opcode_string, ins))
            }
            else {
                // assembled_ins_string = 
                //     if verbose_mode {
                //         format!("0x{:x}\t{}\t{}", ins_base_address, "error", ins)
                //     }
                //     else {
                //         String::from("")
                //     };
                
                // asm_results.push(asm_result);
                // break;
                Err(format!("0x{:016x}\t{}\t{}", ins_base_address, "error", ins))
                // Err(())
                // None
            };

        let err_occurred = assembling_result.is_err();
        
        if verbose_mode {
            // assembled_strings.push(assembled_ins_string);
            let asmed_str = assembling_result.unwrap_or_else(|v| v);
            assembled_strings.push(asmed_str);
        }
        
        if err_occurred {
            break;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if verbose_mode {
            let asm_results = assembled_strings.join("\r\n");
            // println!("{}", asm_results.len());

            let mut tw = tabwriter::TabWriter::new(Vec::new()).padding(4);
            // let mut tw = tabwriter::TabWriter::new(std::io::stdout()).padding(4);
            // write!(&mut tw, &asm_results);
            writeln!(&mut tw, "{}", asm_results)?;
            tw.flush()?;

            let written_strs = String::from_utf8(tw.into_inner()?)?;
            let written_strs = written_strs.split("\r\n").collect::<Vec<&str>>();
            let theme_set = syntect::highlighting::ThemeSet::load_defaults();
            let theme = &theme_set.themes["Solarized (dark)"];
            let syntax_set = syntect::parsing::SyntaxSet::load_defaults_nonewlines();
            let syntax = syntax_set.find_syntax_by_extension("asm").unwrap_or_else(|| syntax_set.find_syntax_plain_text());
            let mut highlighter = syntect::easy::HighlightLines::new(syntax, theme);
            for line in written_strs {
                let ranges: Vec<(syntect::highlighting::Style, &str)> = highlighter.highlight(line);
                let escaped = syntect::util::as_24_bit_terminal_escaped(&ranges[..], true);
                // println!("{}", escaped);
                writeln!(&mut std::io::stdout(), "{}", escaped)?;
            }
        }
    }

    Ok(())
}