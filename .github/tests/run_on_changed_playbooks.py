import argparse
import robot
import os
import subprocess

def get_changed_files_without_extension(base_branch):
    # Run the git diff command to get the changed files compared to the base branch
    result = subprocess.run(
        ['git', 'diff', '--name-only', base_branch],
        stdout=subprocess.PIPE,
        text=True
    )
    
    files = result.stdout.splitlines()

    # Only consider files in the root directory and with .json or .py extensions
    root_files = [
        file for file in files
        if '/' not in file and (file.endswith('.json') or file.endswith('.py'))  # No subdirectories allowed
    ]

    # Remove extensions and only return the files that still exist in the working directory
    files_without_extension = [
        os.path.splitext(file)[0] for file in root_files if os.path.exists(file)
    ]
    
    # Return unique file names without extensions
    return list(set(files_without_extension))

def run_robot_tests(robot_file: str, playbook: str):

    result = robot.run(
        robot_file,
        outputdir='results',
        loglevel='DEBUG:INFO',
        variable=[f"PLAYBOOK:{playbook}"]
    )

    if result == 0:
        print("Tests passed successfully!")
    else:
        print("Tests failed.")



def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(description="Get changed JSON or Python files in the root directory without extensions compared to a base branch")
    
    # Add an argument for the base branch
    parser.add_argument('--base-branch', type=str, help='The base branch to compare against')
    parser.add_argument('--robot-path', type=str, help='Path of the robot test suite')
 
    # Parse the arguments
    args = parser.parse_args()
    
    # Get changed files compared to the provided base branch
    changed_files = get_changed_files_without_extension(args.base_branch)
    
    # Output the files without extensions
    for playbook in changed_files:
        run_robot_tests(args.robot_path, playbook)


if __name__ == "__main__":
    main()