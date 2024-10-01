import os
import subprocess
import argparse

def get_changed_files_without_extension(base_branch):
    # Run the git diff command to get the changed files compared to the base branch
    result = subprocess.run(
        ['git', 'diff', '--name-only', base_branch],
        stdout=subprocess.PIPE,
        text=True
    )
    
    files = result.stdout.splitlines()
    root_files = [
        file for file in files
        if os.path.dirname(file) == '' and (file.endswith('.json') or file.endswith('.py'))
    ]

    files_without_extension = [
        os.path.splitext(file)[0] for file in root_files if os.path.exists(file)
    ]
    
    return list(set(files_without_extension))

def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(description="Get changed JSON or Python files in the root directory without extensions compared to a base branch")
    
    # Add an argument for the base branch
    parser.add_argument('base_branch', type=str, help='The base branch to compare against')
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Get changed files compared to the provided base branch
    changed_files = get_changed_files_without_extension(args.base_branch)
    
    # Output the files without extensions
    for file in changed_files:
        print(file)

if __name__ == "__main__":
    main()