#!/bin/bash
#
# Vim Plugin Git SHA Tracker
#
# This script records and verifies git commit hashes for Vim plugins.
# It can be used to update the SHA database after intentional plugin updates
# or to verify the integrity of existing plugins.
#
# Usage: 
#   ./track-git-shas.sh [PLUGIN_DIR] [OPTIONS]
#
# Options:
#   --update    Update the SHA database with current commit hashes
#   --verify    Verify current commit hashes against database (default)
#   --remote    Check if current hashes exist in remote repositories
#   --help      Display this help message

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHA_DATABASE="${SCRIPT_DIR}/vim-plugin-shas.json"
SCAN_DATE=$(date "+%Y-%m-%d %H:%M:%S")

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Display help message
show_help() {
  echo -e "${BLUE}Vim Plugin Git SHA Tracker${NC}"
  echo -e "This script records and verifies git commit hashes for Vim plugins."
  echo ""
  echo -e "Usage: ./track-git-shas.sh [PLUGIN_DIR] [OPTIONS]"
  echo ""
  echo -e "Options:"
  echo -e "  --update    Update the SHA database with current commit hashes"
  echo -e "  --verify    Verify current commit hashes against database (default)"
  echo -e "  --remote    Check if current hashes exist in remote repositories"
  echo -e "  --help      Display this help message"
  echo ""
  echo -e "Examples:"
  echo -e "  ./track-git-shas.sh ~/.vim/plugged --update"
  echo -e "  ./track-git-shas.sh ~/.vim/plugged --verify --remote"
  exit 0
}

# Check requirements
check_requirements() {
  for tool in git jq; do
    if ! command -v "$tool" &> /dev/null; then
      echo -e "${RED}Error: Required tool not found:${NC} $tool"
      echo "Please install this tool before running the script."
      exit 1
    fi
  done
}

# Initialize the SHA database
initialize_database() {
  if [ ! -f "$SHA_DATABASE" ]; then
    echo "{}" > "$SHA_DATABASE"
    echo -e "${YELLOW}Created new SHA database at:${NC} $SHA_DATABASE"
  else
    echo -e "${GREEN}Using existing SHA database:${NC} $SHA_DATABASE"
  fi
}

# Update SHA database with current values
update_database() {
  echo -e "\n${BLUE}Updating SHA database...${NC}"
  
  local changed=0
  local added=0
  
  # Create a temporary database file
  temp_db=$(mktemp)
  cp "$SHA_DATABASE" "$temp_db"
  
  for plugin_dir in "$PLUGIN_DIR"/*; do
    if [ -d "$plugin_dir/.git" ]; then
      plugin_name=$(basename "$plugin_dir")
      cd "$plugin_dir"
      
      current_hash=$(git rev-parse HEAD)
      remote_url=$(git config --get remote.origin.url)
      last_commit_date=$(git log -1 --format=%cd --date=iso)
      branch=$(git rev-parse --abbrev-ref HEAD)
      
      # Get stored data if exists
      stored_hash=$(jq -r ".[\"$plugin_name\"].hash // \"none\"" "$SHA_DATABASE")
      
      # Update database with jq
      jq --arg name "$plugin_name" \
         --arg hash "$current_hash" \
         --arg remote "$remote_url" \
         --arg date "$last_commit_date" \
         --arg scan_date "$SCAN_DATE" \
         --arg branch "$branch" \
         '.[$name] = {hash: $hash, remote: $remote, commit_date: $date, branch: $branch, last_scan: $scan_date}' \
         "$temp_db" > "${temp_db}.new" && mv "${temp_db}.new" "$temp_db"
      
      if [ "$stored_hash" == "none" ]; then
        echo -e "${GREEN}Added:${NC} $plugin_name ($branch) - $current_hash"
        added=$((added + 1))
      elif [ "$stored_hash" != "$current_hash" ]; then
        echo -e "${YELLOW}Updated:${NC} $plugin_name ($branch) - $stored_hash → $current_hash"
        changed=$((changed + 1))
      fi
    fi
  done
  
  # Move temporary database to final location
  mv "$temp_db" "$SHA_DATABASE"
  
  echo -e "\n${GREEN}SHA database updated successfully.${NC}"
  echo -e "Added $added new plugins, updated $changed existing plugins."
}

# Verify current hashes against database
verify_hashes() {
  echo -e "\n${BLUE}Verifying plugin commit hashes...${NC}"
  
  local mismatch=0
  local match=0
  local missing=0
  
  for plugin_dir in "$PLUGIN_DIR"/*; do
    if [ -d "$plugin_dir/.git" ]; then
      plugin_name=$(basename "$plugin_dir")
      cd "$plugin_dir"
      
      current_hash=$(git rev-parse HEAD)
      current_branch=$(git rev-parse --abbrev-ref HEAD)
      remote_url=$(git config --get remote.origin.url)
      
      # Get stored data
      stored_hash=$(jq -r ".[\"$plugin_name\"].hash // \"none\"" "$SHA_DATABASE")
      stored_remote=$(jq -r ".[\"$plugin_name\"].remote // \"none\"" "$SHA_DATABASE")
      stored_branch=$(jq -r ".[\"$plugin_name\"].branch // \"none\"" "$SHA_DATABASE")
      
      if [ "$stored_hash" == "none" ]; then
        echo -e "${YELLOW}Not tracked:${NC} $plugin_name ($current_branch) - $current_hash"
        missing=$((missing + 1))
      elif [ "$stored_hash" != "$current_hash" ]; then
        echo -e "${RED}Hash mismatch:${NC} $plugin_name"
        echo -e "  Stored:  $stored_hash ($stored_branch)"
        echo -e "  Current: $current_hash ($current_branch)"
        
        # Check if it's a legitimate update by fetching remote info
        if [ "$CHECK_REMOTE" = true ]; then
          git fetch -q origin 2>/dev/null || echo -e "  ${RED}Error:${NC} Could not fetch from remote"
          
          if git merge-base --is-ancestor "$current_hash" "origin/$current_branch" 2>/dev/null || \
             git merge-base --is-ancestor "$current_hash" "origin/HEAD" 2>/dev/null || \
             git merge-base --is-ancestor "$current_hash" "origin/master" 2>/dev/null || \
             git merge-base --is-ancestor "$current_hash" "origin/main" 2>/dev/null; then
            echo -e "  ${GREEN}Verification:${NC} Current hash exists in official repository history"
          else
            echo -e "  ${RED}Warning:${NC} Current hash NOT found in official repository history"
            echo -e "  This could indicate a supply chain attack or unauthorized modification!"
          fi
        fi
        
        mismatch=$((mismatch + 1))
      else
        if [ "$stored_remote" != "$remote_url" ]; then
          echo -e "${RED}Remote URL changed:${NC} $plugin_name"
          echo -e "  Stored:  $stored_remote"
          echo -e "  Current: $remote_url"
          mismatch=$((mismatch + 1))
        else
          echo -e "${GREEN}Hash matches:${NC} $plugin_name - $current_hash"
          match=$((match + 1))
        fi
      fi
    fi
  done
  
  echo -e "\n${BLUE}Verification summary:${NC}"
  echo -e "- Matches: ${GREEN}$match${NC}"
  echo -e "- Mismatches: ${RED}$mismatch${NC}"
  echo -e "- Not tracked: ${YELLOW}$missing${NC}"
  
  if [ $mismatch -gt 0 ]; then
    echo -e "\n${RED}Warning: Found $mismatch plugins with hash mismatches!${NC}"
    echo -e "Run with --update to update the database if these changes are intentional."
    return 1
  elif [ $missing -gt 0 ]; then
    echo -e "\n${YELLOW}Note: Found $missing plugins not in the database.${NC}"
    echo -e "Run with --update to add them to the database."
    return 0
  else
    echo -e "\n${GREEN}All tracked plugins match their expected commit hashes.${NC}"
    return 0
  fi
}

# Check if hashes exist in remote repositories
check_remote_existence() {
  echo -e "\n${BLUE}Checking hash existence in remote repositories...${NC}"
  
  local plugin_count=0
  local not_in_remote=0
  
  for plugin_dir in "$PLUGIN_DIR"/*; do
    if [ -d "$plugin_dir/.git" ]; then
      plugin_name=$(basename "$plugin_dir")
      cd "$plugin_dir"
      
      current_hash=$(git rev-parse HEAD)
      plugin_count=$((plugin_count + 1))
      
      echo -e "Checking ${YELLOW}$plugin_name${NC}..."
      
      # Fetch from remote to ensure we have latest refs
      git fetch -q origin 2>/dev/null || { 
        echo -e "  ${RED}Error:${NC} Could not fetch from remote"
        continue
      }
      
      # Check if current hash exists in main branches
      if git merge-base --is-ancestor "$current_hash" "origin/HEAD" 2>/dev/null || \
         git merge-base --is-ancestor "$current_hash" "origin/master" 2>/dev/null || \
         git merge-base --is-ancestor "$current_hash" "origin/main" 2>/dev/null; then
        echo -e "  ${GREEN}Verified:${NC} Hash exists in official repository history"
      else
        echo -e "  ${RED}Warning:${NC} Hash NOT found in official repository history"
        echo -e "  Current hash: $current_hash"
        echo -e "  This could indicate a supply chain attack or unauthorized modification!"
        not_in_remote=$((not_in_remote + 1))
      fi
    fi
  done
  
  echo -e "\n${BLUE}Remote verification summary:${NC}"
  echo -e "- Plugins checked: $plugin_count"
  echo -e "- Suspicious (not in remote): ${RED}$not_in_remote${NC}"
  
  if [ $not_in_remote -gt 0 ]; then
    echo -e "\n${RED}Warning: Found $not_in_remote plugins with commits not in remote repositories!${NC}"
    echo -e "This may indicate a supply chain attack or unauthorized modifications."
    return 1
  else
    echo -e "\n${GREEN}All plugins have commits that exist in their remote repositories.${NC}"
    return 0
  fi
}

# Main function
main() {
  # Parse arguments
  PLUGIN_DIR=""
  MODE="verify"
  CHECK_REMOTE=false
  
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help)
        show_help
        ;;
      --update)
        MODE="update"
        shift
        ;;
      --verify)
        MODE="verify"
        shift
        ;;
      --remote)
        CHECK_REMOTE=true
        shift
        ;;
      -*)
        echo -e "${RED}Unknown option:${NC} $1"
        show_help
        ;;
      *)
        if [ -z "$PLUGIN_DIR" ]; then
          PLUGIN_DIR="$1"
        else
          echo -e "${RED}Error: Multiple plugin directories specified${NC}"
          show_help
        fi
        shift
        ;;
    esac
  done
  
  # Set default plugin directory if not specified
  PLUGIN_DIR="${PLUGIN_DIR:-$HOME/.vim/plugged}"
  
  if [ ! -d "$PLUGIN_DIR" ]; then
    echo -e "${RED}Error: Plugin directory does not exist:${NC} $PLUGIN_DIR"
    exit 1
  fi
  
  echo -e "${BLUE}Vim Plugin Git SHA Tracker${NC}"
  echo -e "Target: ${YELLOW}$PLUGIN_DIR${NC}"
  echo -e "Mode: ${YELLOW}${MODE}${NC}"
  
  check_requirements
  initialize_database
  
  if [ "$MODE" = "update" ]; then
    update_database
  elif [ "$MODE" = "verify" ]; then
    verify_hashes
    if [ "$CHECK_REMOTE" = true ]; then
      check_remote_existence
    fi
  fi
}

# Run the main function with all arguments
main "$@"