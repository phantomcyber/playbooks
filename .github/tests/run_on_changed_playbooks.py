import argparse
import robot
import os
import subprocess

def get_changed_files_without_extension(base_branch):
    # Run the git diff command to get the changed files compared to the base branch
    result = subprocess.run(
        ['git', 'diff', '--name-only', f"{base_branch}6.3"],
        stdout=subprocess.PIPE,
        text=True
    )

    if result.returncode:
        raise RuntimeError("Failed to check git diff")
    
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

def run_robot_test(robot_file: str, output_dir: str, playbook: str):

    os.makedirs(output_dir, exist_ok=True)

    result = robot.run(
        robot_file,
        outputdir=output_dir,
        loglevel='DEBUG:INFO',
        variable=[f"PLAYBOOK:{playbook}"]
    )

    return result


def main(args):
    
    # Get changed files compared to the provided base branch
    changed_files = get_changed_files_without_extension(args.base_branch)
    
    print(changed_files)
    # Output the files without extensions
    failures = 0
    for playbook in changed_files:
        print(f"\nScanning playbook: {playbook}")
        result = run_robot_test(args.robot_path, os.path.join(args.output_dir, playbook), playbook)
        if result:
            failures += 1

    if failures == 0:
        print("All tests passed successfully!")
    else:
        raise RuntimeError(f"Tests failed on {failures} playbooks.")


if __name__ == "__main__":
    # Create the argument parser
    parser = argparse.ArgumentParser(description="Get changed JSON or Python files in the root directory without extensions compared to a base branch")
    
    # Add an argument for the base branch
    parser.add_argument('--base-branch', type=str, help='The base branch to compare against')
    parser.add_argument('--robot-path', type=str, help='Path of the robot test suite')
    parser.add_argument('--output-dir', type=str, help='Path to results')
 
    # Parse the arguments
    args = parser.parse_args()

    main(args=args)