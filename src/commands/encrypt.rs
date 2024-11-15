use std::{
    fs::File,
    process::exit,
    io::{
        Read,
        Write,
        BufReader,
        BufWriter,
    },
    path::{
        Path,
        PathBuf
    }
};

use crate::{
    KEY,
    ARGS,
    LOGGER,
    LOGDEBUG,
    LOGSUCCESS,
    LOGERROR,
    LOGFATAL
};

use walkdir::WalkDir;

pub fn initialize_encrypt(){
    let args = &ARGS.subcommand_matches("encrypt").unwrap();

    if let Some(path) = args.get_one::<String>("file") {
        let mut counter = 0;
        for entry in WalkDir::new(path).max_depth(1) {
            // Make sure ioc folder is available
            let entry = match entry {
                Ok(valid_entry) => {
                    valid_entry
                }
                Err(e) => {
                    LOGFATAL!("Fatal error encrypting path due to {}",e);
                    exit(2000);
                }
            };
            // Only encrypt if entry is a file
            if entry.file_type().is_file() {
                // Check if file is yar or ioc file
                let extention = Path::new(entry.path()).extension().unwrap();
                // Check if user provided output flag
                let mut new_path: PathBuf;
                if let Some(path) = args.get_one::<String>("output-path") {
                    let tmp_path = Path::new(path);
                    new_path = tmp_path.join(entry.file_name());
                } else {
                    new_path = PathBuf::from(entry.clone().into_path());
                }
                // Read file and try to encrypt them
                if extention == "yara" || extention == "yar" {
                    new_path.set_extension("eyar");
                } else if extention == "ioc" {
                    new_path.set_extension("eioc");
                } else if extention == "cfg" {
                    new_path.set_extension("ecfg");
                } else {
                    LOGDEBUG!("File {} not recognized",entry.file_name().to_str().unwrap());
                    continue;
                }
                let in_file = BufReader::new(File::open(entry.path()).unwrap());
                let out_file = BufWriter::new(File::create(new_path).unwrap());
                match encrypt_file_to_file_buffered(in_file,out_file) {
                    Ok(_) => {
                        LOGSUCCESS!("Encrypted file {}",entry.file_name().to_str().unwrap());
                        counter += 1;
                    }
                    Err(e) => {
                        LOGERROR!("Unable to encrypt file {} due to {}",entry.file_name().to_str().unwrap(),e);
                    }
                }
            }
        }
        if counter == 0 {
            LOGFATAL!("Unable to find a valid ioc or yara file to encrypt");
            exit(2001);
        } else {
            LOGSUCCESS!("Successfully encrypted {} files",counter);
        }
    } else {
        LOGFATAL!("No path was provided");
        exit(2002);
    }
}

pub fn encrypt_file_to_file_buffered(
    mut reader: BufReader<File>,
    mut writer: BufWriter<File>,
) -> Result<(), Box<dyn std::error::Error>> {
    let fernet = fernet::Fernet::new(KEY).unwrap();
    let mut buffer = vec![0; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        writer.write_all(fernet.encrypt(&buffer[0..n]).as_bytes())?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}