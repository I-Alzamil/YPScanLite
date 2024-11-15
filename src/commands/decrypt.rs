use std::{
    fs::File,
    ffi::OsStr,
    process::exit,
    io::{
        BufRead,
        BufReader,
        BufWriter,
        Write
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

pub fn initialize_decrypt(){
    
    let args = ARGS.subcommand_matches("decrypt").unwrap();

    if let Some(path) = args.get_one::<String>("file") {
        let mut counter = 0;
        for entry in WalkDir::new(path).max_depth(1) {
            // Make sure ioc folder is available
            let entry = match entry {
                Ok(valid_entry) => {
                    valid_entry
                }
                Err(e) => {
                    LOGFATAL!("Fatal error decrypting path due to {}",e);
                    exit(3000);
                }
            };
            // Only encrypt if entry is a file
            if entry.file_type().is_file() {
                // Gather metadata about the file
                let filename = entry.file_name().to_str().unwrap_or("N/A");
                let extention = entry.path().extension().unwrap_or(OsStr::new("N/A"));
                // Check if user provided output flag
                let mut new_path: PathBuf;
                if let Some(path) = args.get_one::<String>("output-path") {
                    let tmp_path = Path::new(path);
                    new_path = tmp_path.join(entry.file_name());
                } else {
                    new_path = entry.clone().into_path();
                }
                // Check if file is yar or ioc file
                if extention == "eyar" {
                    new_path.set_extension("yar");
                } else if extention == "eioc" {
                    new_path.set_extension("ioc");
                } else if extention == "ecfg" {
                    new_path.set_extension("cfg");
                } else {
                    LOGDEBUG!("File {} not recognized",filename);
                    continue;
                }
                // Read file and try to encrypt it
                let in_file = BufReader::new(File::open(entry.path()).unwrap());
                let out_file = BufWriter::new(File::create(new_path).unwrap());
                match decrypt_file_to_file_buffered(in_file,out_file) {
                    Ok(_) => {
                        LOGSUCCESS!("Decrypted file {}",filename);
                        counter += 1;
                    }
                    Err(e) => {
                        LOGERROR!("Unable to decrypt file {} due to {}",filename,e);
                    }
                }
            }
        }

        if counter == 0 {
            LOGFATAL!("Unable to find a valid yara or ioc or config file to decrypt");
            exit(3001);
        } else {
            LOGSUCCESS!("Successfully decrypted {} files",counter);
        }
    } else {
        LOGFATAL!("No path was provided");
        exit(3002);
    }
}

pub fn decrypt_file_to_file_buffered(
    mut reader: BufReader<File>,
    mut writer: BufWriter<File>,
) -> Result<(), Box<dyn std::error::Error>> {
    let fernet = fernet::Fernet::new(KEY).unwrap();
    let mut buffer = String::new();
    loop {
        let n = reader.read_line(&mut buffer)?;
        if n == 0 {
            break;
        }
        buffer.pop(); // to remove the new line 
        writer.write_all(&fernet.decrypt(&buffer)?)?;
        buffer.clear();
    }
    writer.flush()?;
    Ok(())
}