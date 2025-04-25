# Vim Plugin Security Scanner

A comprehensive security scanner for Vim plugins that detects supply chain attacks, malicious code, and security vulnerabilities, including advanced obfuscation techniques.

## Overview

This plugin provides robust security scanning for your Vim plugin ecosystem. It integrates with vim-plug to offer security checks before loading plugins, preventing potentially malicious code from executing.

Key features:
- Detects advanced obfuscation techniques used in malicious plugins
- Identifies character-by-character command construction
- Detects register manipulation for hidden command execution
- Finds timer-based delayed execution of malicious code
- Discovers temp file creation and execution chains
- Identifies auto-executing code on common file operations
- Scans for obfuscated malicious code with base64 encoding
- Detects plugins masquerading as system utilities
- Identifies remote code execution attempts
- Tracks git repository hashes to detect tampering
- Provides Vim commands for security operations

## Usage

### Vim Commands

The plugin provides these commands:

- `:SecurityScanAll` - Scan all installed plugins
- `:SecurityScanPlugin {name}` - Scan a specific plugin
- `:SecurityDecodeString {string}` - Decode and analyze a suspicious base64 string

### Configuration

Add these settings to your vimrc to configure:

```vim
" Enable automatic scanning when Vim starts (default: 0)
let g:plugin_security_scan_on_startup = 1

" Block plugins with suspicious code (default: 0)
let g:plugin_security_block_suspicious = 1

" Enable automatic scanning before loading plugins (default: 1)
let g:plugin_security_auto_scan = 1
```

### Manual Scanning

You can run the scripts directly:

```bash
# Full security scan of vim plugins directory
~/.vim/plugged/vim-plugin-security/scripts/scan-vim-plugins.sh ~/.vim/plugged

# Advanced obfuscation detection scan for sophisticated threats
~/.vim/plugged/vim-plugin-security/scripts/detect-advanced-obfuscation.sh ~/.vim/plugged

# Scan using suspicious pattern detector
~/.vim/plugged/vim-plugin-security/scripts/detect-suspicious-patterns.sh ~/.vim/plugged

# Quick scan of just a single plugin
~/.vim/plugged/vim-plugin-security/scripts/scan-vim-plugins.sh ~/.vim/plugged/vim-fugitive

# Update SHA database after intentional plugin updates
~/.vim/plugged/vim-plugin-security/scripts/track-git-shas.sh ~/.vim/plugged --update
```

## Security Features

### Malicious Code Detection

The scanner looks for:

#### Basic Threats
- Obfuscated code execution (base64-encoded commands)
- Remote code execution (curl/wget piped to shell)
- Dynamic execution of string content
- Plugins masquerading as system utilities

#### Advanced Obfuscation Techniques
- Character-by-character string construction to evade detection
- Register manipulation to hide command execution
- Timer-based delayed execution to evade initial scans
- Temp file creation and execution chains
- Auto-executing code on file operations (BufWritePost, etc.)
- Multi-stage execution flows that hide malicious intent

### Supply Chain Attack Prevention

Strategies to prevent supply chain attacks:
- Git hash tracking to detect repository tampering
- Commit verification against official repositories
- Monitoring for unexpected changes to plugins

### Real-Time Protection

When integrated with vim-plug:
- Scans plugins before loading
- Blocks suspicious plugins from executing
- Warns user of potential security threats

## Plugin Structure

- **Scripts**:
  - Core scanning functionality
  - Git hash tracking
  - Suspicious pattern detection

- **Documentation**:
  - Security guidelines
  - Usage documentation

- **Data Storage**:
  - SHA databases
  - Scan reports
  - Configuration files

## Contributing

Contributions welcome! Areas to help with:
- Additional security pattern detection
- Performance improvements
- Documentation enhancement
- Test coverage
- New obfuscation detection methods

## License

MIT License - See LICENSE file for details.
