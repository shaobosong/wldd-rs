//! A library for analyzing PE (Portable Executable) file dependencies, similar to the `ldd` tool on Linux.
//!
//! This library provides functionality to:
//! - Parse PE files and extract their dynamic dependencies
//! - Search for dependencies in specified directories
//! - Report missing dependencies
//!
//! # Examples
//!
//! Basic usage:
//!
//! ```no_run
//! use wldd_rs::{Config, run};
//!
//! let config = Config {
//!     dir: vec!["C:\\Windows\\System32".into()],
//!     files: vec!["my_program.exe".into()],
//! };
//!
//! run(config).unwrap();
//! ```

use std::{
    fs,
    io,
    path::{Path, PathBuf},
};

use clap::Parser;
use goblin::pe;
use memmap2::Mmap;
use thiserror::Error;

/// Configuration options for the dependency analyzer
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    /// Additional directories to search for dependencies
    #[arg(short, long, value_name = "DIRECTORY")]
    pub dirs: Vec<PathBuf>,

    /// Files to analyze (at least one required)
    #[arg(required = true)]
    pub files: Vec<PathBuf>,
}

/// Error type for all operations in this crate
#[derive(Error, Debug)]
pub enum WlddError {
    /// Wrapper for I/O errors
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    /// Errors related to file validation
    #[error("File error: {0}")]
    FileError(String),

    /// Errors realted to directory validation
    #[error("Invalid search directory: {0}")]
    InvalidDirectory(String),

    /// Errors occurring during PE file parsing
    #[error("PE parse error: {0}")]
    PeParseError(String),
}

/// Main entry point for analyzing PE file dependencies
///
/// # Arguments
/// * `config` - Configuration specifying files to analyze and search directories
///
/// # Returns
/// * `Ok(())` if all files were processed (even if dependencies are missing)
/// * `Err(WlddError)` if a fatal error occurred
///
/// # Examples
/// ```
/// # use wldd_rs::{Config, run};
/// # let config = Config { dir: vec![], files: vec![] };
/// if let Err(e) = run(config) {
///     eprintln!("Error: {}", e);
/// }
/// ```
pub fn run(config: Config) -> Result<(), WlddError> {
    for dir in &config.dirs {
        validate_dir(dir)?;
    }

    for file in &config.files {
        validate_file(file)?;

        let deps = get_pe_dependencies(file)?;
        if deps.is_empty() {
            eprintln!("{}: not a dynamic executable", file.display());
            continue;
        }

        println!("{}:", file.display());
        check_dependencies(&deps, &config.dirs);
    }

    Ok(())
}

/// Validates that a path exists and is a regular file
///
/// # Arguments
/// * `file` - Path to the file to validate
///
/// # Returns
/// * `Ok(())` if the file is valid
/// * `Err(WlddError::FileError)` if the file doesn't exist or isn't a regular file
fn validate_file(file: &Path) -> Result<(), WlddError> {
    if !file.exists() {
        Err(WlddError::FileError(format!("{}: No such file or directory", file.display())))
    } else if !file.is_file() {
        Err(WlddError::FileError(format!("{}: not regular file", file.display())))
    } else {
        Ok(())
    }
}

/// Validates that a path exists and is a directory
///
/// # Arguments
/// * `dir` - Path to the directory to validate
///
/// # Returns
/// * `Ok(())` if the directory is valid
/// * `Err(WlddError::InvalidDirectory)` if the directory doesn't exist or isn't a directory
fn validate_dir(dir: &Path) -> Result<(), WlddError> {
    if !dir.exists() || !dir.is_dir() {
        Err(WlddError::InvalidDirectory(dir.display().to_string()))
    } else {
        Ok(())
    }
}

/// Extracts dependencies from a PE file
///
/// # Arguments
/// * `file_path` - Path to the PE file to analyze
///
/// # Returns
/// * `Ok(Vec<String>)` - List of dependency filenames
/// * `Err(WlddError)` - If the file couldn't be read or parsed
///
/// # Notes
/// This function uses memory mapping for efficient file access
fn get_pe_dependencies(file_path: &Path) -> Result<Vec<String>, WlddError> {
    let file = fs::File::open(file_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let pe = pe::PE::parse(&mmap).map_err(|e| WlddError::PeParseError(e.to_string()))?;

    let mut deps = Vec::new();

    for import in pe.libraries.iter() {
        deps.push(import.to_string());
    }

    Ok(deps)
}

/// Checks where dependencies are found in the search paths
///
/// # Arguments
/// * `deps` - List of dependency filenames to search for
/// * `dirs` - Directories to search in
///
/// # Output
/// Prints to stdout for each dependency:
/// - The path where it was found (if any)
/// - "Not found" if the dependency wasn't found in any search directory
fn check_dependencies(deps: &[String], dirs: &[PathBuf]) {
    let max_len = deps.iter().map(|d| d.len()).max().unwrap_or(0);

    for dep in deps {
        let mut found = false;
        for dir in dirs {
            let dep_path = dir.join(dep);
            if dep_path.is_file() {
                if !found {
                    println!("\t{:width$} => {}", dep, dir.display(), width = max_len);
                    found = true;
                } else {
                    println!("\t{:width$} => {}", "", dir.display(), width = max_len);
                }
            }
        }
        if !found {
            println!("\t{:width$} => Not found", dep, width = max_len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Tests that a valid file passes validation
    #[test]
    fn test_validate_file() {
        let temp_file = NamedTempFile::new().unwrap();
        assert!(validate_file(temp_file.path()).is_ok());
    }

    /// Tests that a non-existent file fails validation
    #[test]
    fn test_validate_nonexistent_file() {
        let result = validate_file(Path::new("/nonexistent/file"));
        assert!(result.is_err());
    }
}
