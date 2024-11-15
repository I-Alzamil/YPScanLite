use std::{
    thread,
    sync::Arc,
    path::Path,
    sync::RwLock,
    process::exit,
    ffi::OsString,
    time::Duration,
    collections::HashSet

    
};

use yara_x::{
    Rules,
    Scanner
};

use sysinfo::Disks;
use regex::RegexSet;
use walkdir::WalkDir;
use chrono::DateTime;
use queue_file::QueueFile;
use indicatif::FormattedDuration;
use concurrent_queue::ConcurrentQueue;

use crate::{
    LOGTRACE,
    LOGDEBUG,
    LOGRESULT,
    LOGNOTICE,
    LOGALERT,
    LOGERROR,
    LOGFATAL,
    CREATEPROGRESS,
    INCLENGTHPROGRESS,
    INCPROGRESS,
    DELETEPROGRESS,
    utils::{
        hasher::*,
        args::ARGS,
        statics::{
            LOGGER,
            MY_PATH
        }
    }
};

pub fn initialize_filescan(
    rules: Arc<Option<Rules>>,
    malware_hashes: Arc<Option<HashSet<String>>>,
    excluded_hashes: Arc<Option<HashSet<String>>>,
    excluded_paths: Option<RegexSet>
) {
    // Check if both yara and hashes are disabled
    if rules.is_none() && malware_hashes.is_none() {
        LOGFATAL!("Both yara and ioc files failed to load, unable to start scan");
        exit(1000);
    }
    
    let args = ARGS.subcommand_matches("scan").unwrap();

    // Setup in-memory queue and cap it to 1000 items in order to save RAM
    let job_queue: Arc<ConcurrentQueue<OsString>> = Arc::new(ConcurrentQueue::bounded(1000));

    // Setup disk queue which is used incase in-memory queue gets full
    let tempfile = std::env::temp_dir().join("ypsqueue.db");
    if tempfile.exists() {
        LOGNOTICE!("It appears last scan exited unsucessfully, attempting reset");
        match std::fs::remove_file(tempfile.as_path()) {
            Ok(_) => LOGNOTICE!("Successful reset"),
            Err(e) => LOGERROR!("Unable to delete temp file due to {}, reset failed",e),
        }
    }
    let mut disk_queue = match QueueFile::open(tempfile.as_path()) {
        Ok(valid_queue) => valid_queue,
        Err(e) => {
            LOGFATAL!("Failed to create disk queue due to {e}");
            exit(1004)
        }
    };
    disk_queue.set_sync_writes(false);

    // Get list of paths to scan
    let mut scan_paths: Vec<&Path> = Vec::new();
    let disks = Disks::new_with_refreshed_list();

    // Check if user provied path argument, if not check os and use default option
    if let Some(path) = args.get_one::<String>("path") {
        scan_paths.push(Path::new(path));
    } else {
        if std::env::consts::OS == "windows" {
            for disk in disks.list() {
                if args.contains_id("all-drives") {
                    scan_paths.push(disk.mount_point());
                } else {
                    if !disk.is_removable() {
                        scan_paths.push(disk.mount_point());
                    }
                }
            }
        } else {
            scan_paths.push(Path::new("/"));
        }
    }

    let max_threads: u8;

    // Determine threads count
    if let Some(threads) = args.get_one::<u8>("threads") {
        max_threads = *threads;
    } else {
        // by default run using half the resources
        let mut sys = sysinfo::System::new();
        sys.refresh_cpu_all();
        if args.get_flag("power") {
            max_threads = sys.cpus().len() as u8;
        } else {
            max_threads = sys.cpus().len() as u8 / 2;
        }
    }

    LOGDEBUG!("Threads count set to {}",max_threads);

    let found_match = Arc::new(RwLock::new(false));

    // Spawn worker threads
    let mut handlers: Vec<thread::JoinHandle<()>> = Vec::new();
    for _ in 0..max_threads {
        let shared_rules = Arc::clone(&rules);
        let shared_queue = Arc::clone(&job_queue);
        let shared_malware_hashes = Arc::clone(&malware_hashes);
        let shared_excluded_hashes = Arc::clone(&excluded_hashes);
        let shared_found_match = Arc::clone(&found_match);
        handlers.push(thread::spawn(move || {

            let no_progress = ARGS.subcommand_matches("scan").unwrap().get_flag("no-progress");

            fn inc_progress(no_progress: bool) {
                if !no_progress {
                    INCPROGRESS!(1);
                }
            }

            fn get_reason_number(size: usize) -> usize {
                return (size / 3) + 1
            }
            
            // Setup yara thread scanner if rules is available
            let mut scanner: Option<Scanner<'_>>;
            match *shared_rules {
                Some(ref rules) => scanner = Some(Scanner::new(rules)),
                None => scanner = None,
            }

            // Setup vecs to be used in scan
            let mut info_vec: Vec<(String,String)> = Vec::new();

            let mut result_vec: Vec<(String,String)> = Vec::new();

            let info = &mut info_vec;
            let result = &mut result_vec;

            // Main loop
            loop {
                
                // Exit worker thread if queue is closed (finished adding files) and is empty
                if shared_queue.is_closed() && shared_queue.is_empty() {
                    break;
                }

                // Get a file from the queue
                let entry = match shared_queue.pop() {
                    Ok(valid_entry) => {
                        valid_entry
                    }
                    Err(e) => {
                        LOGTRACE!("Couldn't pop from queue due to {}",e);
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                };

                info.clear();
                result.clear();

                let file = Path::new(&entry);

                LOGTRACE!("Start scanning {}",file.display());

                info.push((format!("Path"),format!("{}",file.display())));

                let created_timestame: String;
                let modified_timestame: String;
                let accessed_timestame: String;
                let file_size = get_file_size(file);

                match file.metadata() {
                    Ok(metadata) => {
                        created_timestame = match metadata.created() {
                            Ok(valid_timestamp) => DateTime::<chrono::Utc>::from(valid_timestamp).format("%d/%m/%Y %T").to_string(),
                            Err(_) => format!("N/A"),
                        };
                        modified_timestame = match metadata.modified() {
                            Ok(valid_timestamp) => DateTime::<chrono::Utc>::from(valid_timestamp).format("%d/%m/%Y %T").to_string(),
                            Err(_) => format!("N/A"),
                        };
                        accessed_timestame = match metadata.accessed() {
                            Ok(valid_timestamp) => DateTime::<chrono::Utc>::from(valid_timestamp).format("%d/%m/%Y %T").to_string(),
                            Err(_) => format!("N/A"),
                        };
                    }
                    Err(e) => {
                        LOGDEBUG!("Unable to get metadata due to {}",e);
                        created_timestame = format!("N/A");
                        modified_timestame = format!("N/A");
                        accessed_timestame = format!("N/A");
                    }
                };

                let file_type = match file_format::FileFormat::from_file(file) {
                    Ok(ftype) => ftype.name().to_string(),
                    Err(e) => {
                        LOGDEBUG!("Unable to get file type due to {}",e);
                        format!("N/A")
                    }
                };

                info.push((format!("Type"),file_type.clone()));
                info.push((format!("Size"),file_size.to_string()));
                info.push((format!("Created"),created_timestame));
                info.push((format!("Modified"),modified_timestame));
                info.push((format!("Accessed"),accessed_timestame));

                info.push((format!("Signature"),get_file_signature(file)));
                
                match hash_all(file) {
                    Ok(valid_hashes) => {
                        match *shared_excluded_hashes {
                            Some(ref excluded_hashes) => {
                                if excluded_hashes.contains(&valid_hashes[0]) || excluded_hashes.contains(&valid_hashes[1]) || excluded_hashes.contains(&valid_hashes[2]) {
                                    LOGDEBUG!("Skipping file {} due to a match in hash exclusions",file.display());
                                    continue;
                                }
                            }
                            None => {}
                        }
                        match *shared_malware_hashes {
                            Some(ref malware_hashes) => {
                                if malware_hashes.contains(&valid_hashes[0]) {
                                    if !*shared_found_match.read().unwrap() {
                                        let mut lock = shared_found_match.write().unwrap();
                                        *lock = true;
                                    }
                                    result.push((format!("MatchReason_{}",get_reason_number(result.len())),format!("Hash Match")));
                                    result.push((format!("MatchName_{}",get_reason_number(result.len())),format!("MD5")));
                                    result.push((format!("MatchDesc_{}",get_reason_number(result.len())),format!("Matched {}",&valid_hashes[0])));
                                }
                                if malware_hashes.contains(&valid_hashes[1]) {
                                    if !*shared_found_match.read().unwrap() {
                                        let mut lock = shared_found_match.write().unwrap();
                                        *lock = true;
                                    }
                                    result.push((format!("MatchReason_{}",get_reason_number(result.len())),format!("Hash Match")));
                                    result.push((format!("MatchName_{}",get_reason_number(result.len())),format!("SHA1")));
                                    result.push((format!("MatchDesc_{}",get_reason_number(result.len())),format!("Matched {}",&valid_hashes[1])));
                                }
                                if malware_hashes.contains(&valid_hashes[2]) {
                                    if !*shared_found_match.read().unwrap() {
                                        let mut lock = shared_found_match.write().unwrap();
                                        *lock = true;
                                    }
                                    result.push((format!("MatchReason_{}",get_reason_number(result.len())),format!("Hash Match")));
                                    result.push((format!("MatchName_{}",get_reason_number(result.len())),format!("SHA256")));
                                    result.push((format!("MatchDesc_{}",get_reason_number(result.len())),format!("Matched {}",&valid_hashes[2])));
                                }
                            }
                            None => {}
                        }
                        info.push((format!("MD5"),format!("{}",&valid_hashes[0])));
                        info.push((format!("SHA1"),format!("{}",&valid_hashes[1])));
                        info.push((format!("SHA256"),format!("{}",&valid_hashes[2])));
                    }
                    Err(e) => {
                        LOGDEBUG!("Unable to scan file {} due to {}",file.display(),e);
                        inc_progress(no_progress);
                        continue;
                    }
                }
                
                // Run scanner if it is available
                match scanner {
                    Some(ref mut valid_scanner) => {
                        // Add additional fields to scanner
                        let _ = valid_scanner.set_global("filename", file.file_name().unwrap_or_default().to_str().unwrap_or("N/A"));
                        let _ = valid_scanner.set_global("filepath", file.to_str().unwrap_or("N/A"));
                        let _ = valid_scanner.set_global("filetype", file_type);
                        let _ = valid_scanner.set_global("extension", file.extension().unwrap_or_default().to_str().unwrap_or("N/A"));

                        // Scan the file using yara rules and get results
                        match valid_scanner.scan_file(file) {
                            Ok(yara_result) => {
                                for rule_match in yara_result.matching_rules() {
                                    if !*shared_found_match.read().unwrap() {
                                        let mut lock = shared_found_match.write().unwrap();
                                        *lock = true;
                                    }
                                    let rule_number = get_reason_number(result.len());
                                    if rule_number > 9 && !args.get_flag("all-reasons") {
                                        break;
                                    }
                                    result.push((format!("MatchReason_{}",rule_number),format!("Yara Match")));
                                    result.push((format!("MatchName_{}",rule_number),rule_match.identifier().to_string()));
                                    let metadata: yara_x::Metadata<'_, '_> = rule_match.metadata();
                                    let mut description = format!("N/A");
                                    let mut has_author = false;
                                    let mut author = format!("N/A");
                                    for data in metadata {
                                        if data.0.to_lowercase() == "description" {
                                            description = match data.1 {
                                                yara_x::MetaValue::Integer(value) => format!("{value}"),
                                                yara_x::MetaValue::Float(value) => format!("{value}"),
                                                yara_x::MetaValue::Bool(value) => format!("{value}"),
                                                yara_x::MetaValue::String(value) => format!("{value}"),
                                                yara_x::MetaValue::Bytes(value) => format!("{value}"),
                                            }
                                        }
                                        if data.0.to_lowercase() == "author" {
                                            author = match data.1 {
                                                yara_x::MetaValue::Integer(value) => format!("{value}"),
                                                yara_x::MetaValue::Float(value) => format!("{value}"),
                                                yara_x::MetaValue::Bool(value) => format!("{value}"),
                                                yara_x::MetaValue::String(value) => format!("{value}"),
                                                yara_x::MetaValue::Bytes(value) => format!("{value}"),
                                            };
                                            has_author = true;
                                        }
                                    }
                                    if has_author {
                                        result.push((format!("MatchDesc_{}",get_reason_number(result.len())),format!("{}. Made by {}.",description,author)));
                                    } else {
                                        result.push((format!("MatchDesc_{}",get_reason_number(result.len())),description));
                                    }
                                }
                            }
                            Err(e) => {
                                LOGDEBUG!("Unable to scan file {} due to {}",file.display(),e);
                                inc_progress(no_progress);
                                continue;
                            }
                        }
                    }
                    None => {}
                }
                    

                if !result.is_empty() {
                    info.append(result);
                    LOGALERT!(kvl: info,"MATCH FOUND");
                } else {
                    LOGTRACE!(kvl: info,"Finished scanning file without any match")
                }

                inc_progress(no_progress);
            }
        }));
    }

    if !args.get_flag("no-progress") {
        CREATEPROGRESS!(0);
    }

    let file_size_limit: u64;

    if let Some(size) = args.get_one::<u64>("size") {
        // Get file size in KB
        file_size_limit = *size * 1000;
    } else if args.get_flag("no-size") {
        file_size_limit = 0;
    } else {
        file_size_limit = 150000000;
    }

    let start_time = std::time::Instant::now();

    // Start walkdir and fetch all files to be scanned and add them to the queue
    for scan_path in scan_paths {
        for entry in WalkDir::new(scan_path)
            .into_iter()
            .filter_entry(|e| !excluded_entry(e,&excluded_paths))
        {
            let entry = match entry {
                Ok(validentry) => {
                    // Skip if file is under scanner path to avoid falce positives
                    if validentry.path().starts_with(&MY_PATH.as_path()) {
                        continue;
                    }
                    validentry
                }
                Err(e) => {
                    LOGDEBUG!("Unable to scan directory due to {}",e);
                    continue;
                }
            };
            if entry.file_type().is_file() {
                // Check if size is limited
                if file_size_limit != 0 {
                    let file_size = get_file_size(entry.path());

                    if file_size >= file_size_limit {
                        LOGTRACE!("File {} skiped due to file size",entry.file_name().to_str().unwrap());
                        continue;
                    }
                }
                
                match job_queue.push(entry.path().as_os_str().to_os_string()) {
                    Ok(_) => {} // This means we are below 1000 items in the queue.
                    Err(_) => {
                        // Put path to the disk queue instead.
                        match disk_queue.add(entry.path().as_os_str().as_encoded_bytes()) {
                            Ok(_) => {}
                            Err(e) => {
                                LOGFATAL!("Unable to add to disk queue file due to {}, scan will abort now",e);
                                exit(1001);
                            }
                        }
                    }
                }

                if !args.get_flag("no-progress") {
                    INCLENGTHPROGRESS!(1);
                }
            }
        }
    }

    // Make sure to clear disk_queue before proceeding
    loop {
        match disk_queue.peek() {
            Err(e) => {
                LOGFATAL!("Unable to read disk queue file due to {}, scan will abort now",e);
                exit(1002);
            }
            Ok(item) => {
                match item {
                    None => {
                        LOGTRACE!("Disk queue file is now empty and the process of dequeuing is done");
                        match std::fs::remove_file(tempfile.as_path()) {
                            Ok(_) => LOGTRACE!("Sucessfully remove temp file"),
                            Err(e) => LOGERROR!("Unable to delete temp file due to {}",e),
                        }
                        break;
                    }
                    Some(bytes) => {
                        let path = unsafe {
                            OsString::from_encoded_bytes_unchecked(bytes.to_vec())
                        };
                        match job_queue.push(path) {
                            Ok(_) => {
                                // This means we are below 1000 items in the queue and have successfully pushed to it

                                // Remove item from queue since we already pushed to job_queue
                                match disk_queue.remove() {
                                    Ok(_) => {}
                                    Err(e) => {
                                        LOGFATAL!("Unable to remove from disk queue file due to {}, scan will abort now",e);
                                        exit(1003);
                                    }
                                }
                            }
                            Err(_) => {
                                // Wait for workers to consume more work
                                LOGTRACE!("Job queue is full, Waiting for worker threads to consume more items");
                                std::thread::sleep(Duration::from_millis(100));
                            }
                        }
                        
                    }
                }
            }
        }
    }

    // Close job queue to signal to worker threads they can exit if queue is empty
    job_queue.close();

    // Wait for threads to finish
    for handle in handlers {
        match handle.join() {
            Ok(_) => {
                LOGTRACE!("Worker thread successfully closed");
            }
            Err(e) => {
                LOGERROR!("Error closing worker thread due to {:?}",e);
            }
        }
    }

    let elapsed = FormattedDuration(start_time.elapsed());

    LOGNOTICE!("Scan have completed in {}",elapsed);

    if *found_match.read().unwrap() {
        LOGRESULT!(clean: false,"Matches were found");
        LOGRESULT!(clean: false,"Review matched files as you see fit and proceed with caution");
    } else {
        LOGRESULT!(clean: true,"No matches were found during scan");
        LOGRESULT!(clean: true,"Result is clean");
    }

    // Delete progress if it is active
    DELETEPROGRESS!();
}

#[cfg(target_os = "windows")]
fn excluded_entry(
    entry: &walkdir::DirEntry,
    regex_set: &Option<RegexSet>
) -> bool {
    let excluded = match regex_set {
        Some(set) => {
            entry.path()
                .to_str()
                .map(|s| set.is_match(s))
                .unwrap_or(false)
        }
        None => return false,
    };
    if excluded {
        LOGDEBUG!("Skipping {} due to a match in path exclusions",entry.path().display());
    }
    return excluded;
}

#[cfg(target_os = "windows")]
fn get_file_signature(entry: &Path) -> String {
    return match codesign_verify::CodeSignVerifier::for_file(&entry) {
        Ok(valid_verfiy) => {
            match valid_verfiy.verify() {
                Ok(valid_context) => format!("{}",valid_context.subject_name().common_name.unwrap_or("N/A".to_string())),
                Err(codesign_verify::Error::Unsigned) => {
                    format!("Unsigned")
                }
                Err(e) => {
                    LOGDEBUG!("failed to get certificate for {} due to {:?}",entry.display(),e);
                    format!("IOError")
                }
            }
        }
        Err(e) => format!("{:?}",e),
    };
}

#[cfg(target_os = "windows")]
fn get_file_size(entry: &Path) -> u64 {
    use std::os::windows::fs::MetadataExt;
    return match entry.metadata() {
        Ok(valid_metadata) => valid_metadata.file_size(),
        Err(_) => 0,
    };
}

#[cfg(not(target_os = "windows"))]
pub const LINUX_EXCLUSIONS: [&str;2] = ["/proc","/sys"];

#[cfg(not(target_os = "windows"))]
fn excluded_entry(
    entry: &walkdir::DirEntry,
    regex_set: &Option<RegexSet>
) -> bool {
    if entry.file_type().is_dir() {
        let excluded = entry.path()
            .to_str()
            .map(|s| LINUX_EXCLUSIONS.contains(&s))
            .unwrap_or(false);
        if excluded {
            return true;
        }
    }
    let excluded = match regex_set {
        Some(set) => {
            entry.path()
                .to_str()
                .map(|s| set.is_match(s))
                .unwrap_or(false)
        }
        None => return false,
    };
    if excluded {
        LOGDEBUG!("Skipping {} due to a match in path exclusions",entry.path().display());
    }
    return excluded;
}

#[cfg(not(target_os = "windows"))]
fn get_file_signature(_entry: &Path) -> String {
    return format!("N/A");
}

#[cfg(not(target_os = "windows"))]
fn get_file_size(entry: &Path) -> u64 {
    use std::os::linux::fs::MetadataExt;
    return match entry.metadata() {
        Ok(valid_metadata) => valid_metadata.st_size(),
        Err(_) => 0,
    };
}