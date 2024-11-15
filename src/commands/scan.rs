use std::{
    sync::Arc,
    collections::HashSet,
    fs::{
        self,
        File
    },
    io::{
        Write,
        BufRead,
        BufReader,
        BufWriter
    },
    path::{
        Path,
        PathBuf
    }
};

use crate::{
    KEY,
    ARGS,
    LOGDEBUG,
    LOGINFO,
    LOGNOTICE,
    LOGWARN,
    LOGERROR,
    modules::filescan::initialize_filescan,
    utils::statics::{
        LOGGER,
        MY_PATH
    },
};

use regex::{
    Regex,
    RegexSet
};

use walkdir::WalkDir;
use yara_x::Rules;

fn check_arguments_and_display_info() {
    
    let args = ARGS.subcommand_matches("scan").unwrap();

    let size_message: String;

    if let Some(size) = args.get_one::<u64>("size") {
        size_message = format!("File size limit set to {} KB",size);
    } else if args.get_flag("no-size") {
        size_message = format!("File size limit is removed");
    } else {
        size_message = format!("Default file size limit set to 150 MB");
    }

    if let Some(path) = args.get_one::<String>("path") {
        LOGINFO!("Scanning {}",path);
    } else {
        LOGINFO!("Scanning all drives (Excluding removable and share)");
    }

    LOGINFO!("{}",size_message);
}

pub fn initialize_scan() {
    
    check_arguments_and_display_info();

    let rules = load_yara_files(Path::new("yara"));
    let malware_hashes = load_malware_hashes(Path::new("iocs"));
    let excluded_hashes = load_excluded_hashes(Path::new("config"));
    let excluded_paths = load_excluded_paths(Path::new("config"));

    initialize_filescan(rules,malware_hashes,excluded_hashes,excluded_paths);
}

fn load_file(file_path: &Path,encrypted: bool) -> Result<String,Box<dyn std::error::Error>> {

    let loaded_string: String;

    if encrypted {
        let in_file = BufReader::new(File::open(file_path)?);
        let mut out_string = BufWriter::new(Vec::new());
        decrypt_file_to_string_buffered(in_file,&mut out_string)?;
        let bytes = out_string.into_inner()?;
        loaded_string = String::from_utf8(bytes)?;
    } else {
        loaded_string = fs::read_to_string(file_path)?;
    }

    Ok(loaded_string)
}

fn preload_paths(dir_path: &Path,file_extension: &str,encrypted_file_extension: &str) -> Result<Vec<(PathBuf,bool)>,Box<dyn std::error::Error>> {
    let mut all_preloaded_paths: Vec<(PathBuf,bool)> = Vec::new();

    'outer: for entry in WalkDir::new(MY_PATH.join(dir_path)).max_depth(1) {

        let dir_entry = entry?;

        if dir_entry.file_type().is_file() {
            // Extract extension
            let extention = match dir_entry.path().extension() {
                Some(valid_extention) => valid_extention.to_str().unwrap_or(""),
                None => "",
            };
            // Map if file is encrypted or not
            let splited_ext = file_extension.split(";");
            for ext in splited_ext {
                if extention.eq_ignore_ascii_case(ext) {
                    all_preloaded_paths.push((dir_entry.into_path(),false));
                    continue 'outer;
                }
            }
            if extention.eq_ignore_ascii_case(encrypted_file_extension) {
                all_preloaded_paths.push((dir_entry.into_path(),true));
            }
        }
    }

    Ok(all_preloaded_paths)
}

fn load_yara_files(dir_path: &Path) -> Arc<Option<Rules>> {

    let mut compiler = yara_x::Compiler::new();
    let _ = compiler.define_global("filename", "");
    let _ = compiler.define_global("filepath", "");
    let _ = compiler.define_global("filetype", "");
    let _ = compiler.define_global("extension", "");
    let _ = compiler.define_global("owner", "");

    let mut counter = 0;

    let files = match preload_paths(dir_path,"yara;yar","eyar") {
        Ok(valid_vec) => valid_vec,
        Err(_) => {
            LOGWARN!("Unable to locate yara directory, yara scan is disabled");
            return Arc::new(None);
        }
    };

    for file in files {
        
        let rule_content = match load_file(file.0.as_path(),file.1) {
            Ok(valid_file) => valid_file,
            Err(e) => {
                LOGERROR!("Unable to load a file {} due to {}",file.0.display(),e);
                continue;
            }
        };

        // Make sure yara folder is available
        match compiler.add_source(rule_content.as_bytes()){
            Ok(_) => {
                LOGDEBUG!("Successfully loaded {}",file.0.display());
                counter += 1;
            }
            Err(e) => {
                LOGERROR!("Error loading yara rule {} due to {}",file.0.display(),e);
            }
        }
    }

    if counter != 0 {
        LOGINFO!("Successfully parsed {} yara rule files",counter);
        let rules = compiler.build();
        LOGINFO!("Successfully loaded {} yara rules",rules.iter().count());
        return Arc::new(Some(rules));
    } else {
        LOGWARN!("No yara file was loaded, yara scan is disabled");
        return Arc::new(None);
    }
}

fn load_malware_hashes(dir_path: &Path) -> Arc<Option<HashSet<String>>> {

    let mut hashes: HashSet<String> = HashSet::new();
    
    let mut counter = 0;

    let files = match preload_paths(dir_path,"ioc","eioc") {
        Ok(valid_vec) => valid_vec,
        Err(_) => {
            LOGWARN!("Unable to locate ioc directory, hash scan is disabled");
            return Arc::new(None);
        }
    };

    for file in files {
        
        let ioc_content = match load_file(file.0.as_path(),file.1) {
            Ok(valid_file) => valid_file,
            Err(e) => {
                LOGERROR!("Unable to load a file {} due to {}",file.0.display(),e);
                continue;
            }
        };

        // Read hash file line by line
        for line in ioc_content.lines() {
            // Parse hashes
            if line.starts_with("#") || line.is_empty() {
                continue;
            }
            let mut parsed = line.split(";");
            let hash = parsed.next().unwrap();
            hashes.insert(hash.to_string());
            counter += 1;
        }
    }

    if counter != 0 {
        LOGINFO!("Successfully loaded {} malware hashes",counter);
        return Arc::new(Some(hashes));
    } else {
        LOGWARN!("No malware hash was loaded, hash scan is disabled");
        return Arc::new(None);
    }
}

fn load_excluded_hashes(dir_path: &Path) -> Arc<Option<HashSet<String>>> {

    let mut hashes: HashSet<String> = HashSet::new();

    let binding = MY_PATH.join(dir_path);
    let adjusted_dir_path = binding.as_path();

    // try to load config file
    let hashes_content = match load_file(adjusted_dir_path.join("hash-exclusions.cfg").as_path(),false) {
        Ok(valid_file) => Some(valid_file),
        Err(_) => {
            // if unsuccessful try to load encrypted config file
            match load_file(adjusted_dir_path.join("hash-exclusions.ecfg").as_path(),true) {
                Ok(valid_file) => Some(valid_file),
                Err(_) => None,
            }
        }
    };

    match hashes_content {
        Some(content) => {
            // Read hash file line by line
            let mut counter = 0;
            for line in content.lines() {
                // Parse hashes
                if line.starts_with("#") || line.is_empty() {
                    continue;
                }
                let mut parsed = line.split(";");
                let hash = parsed.next().unwrap();
                hashes.insert(hash.to_string());
                counter += 1;
            }
            if counter != 0 {
                LOGINFO!("Successfully loaded {} excluded hashes",counter);
                return Arc::new(Some(hashes));
            } else {
                LOGDEBUG!("No hash was excluded");
                return Arc::new(None);
            }
        }
        None => {
            LOGNOTICE!("Hash exclusion config file was not found");
            return Arc::new(None);
        }
    }
}

fn load_excluded_paths(dir_path: &Path) -> Option<RegexSet> {

    let binding = MY_PATH.join(dir_path);
    let adjusted_dir_path = binding.as_path();
    
    // try to load config file
    let paths_content = match load_file(adjusted_dir_path.join("path-exclusions.cfg").as_path(),false) {
        Ok(valid_file) => Some(valid_file),
        Err(_) => {
            // if unsuccessful try to load encrypted config file
            match load_file(adjusted_dir_path.join("path-exclusions.ecfg").as_path(),true) {
                Ok(valid_file) => Some(valid_file),
                Err(_) => None,
            }
        }
    };

    match paths_content {
        Some(content) => {
            // Read hash file line by line
            let mut counter = 0;
            let mut patterns: Vec<&str> = Vec::new();
            for line in content.lines() {
                // Parse hashes
                if line.starts_with("#") || line.is_empty() {
                    continue;
                }
                match Regex::new(line) {
                    Ok(_) => {
                        patterns.push(line);
                        counter += 1;
                    }
                    Err(e) => {
                        LOGERROR!("Unable to compile regex '{}' due to {}",line,e);
                    }
                }
            }
            if counter != 0 {
                LOGINFO!("Successfully loaded {} excluded paths",counter);
                match RegexSet::new(patterns) {
                    Ok(set) => {
                        return Some(set);
                    }
                    Err(e) => {
                        LOGERROR!("Unable to read regex exclusions due to {}",e);
                        return None;
                    }
                }
            } else {
                LOGDEBUG!("No path was excluded");
                return None;
            }
        }
        None => {
            LOGNOTICE!("Path exclusion config file was not found");
            return None;
        }
    }
}

pub fn decrypt_file_to_string_buffered(
    mut reader: BufReader<File>,
    writer: &mut BufWriter<Vec<u8>>,
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