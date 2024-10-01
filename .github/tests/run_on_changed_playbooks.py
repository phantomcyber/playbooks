import argparse
import robot
from find_changed_playbooks import get_changed_files_without_extension

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
    parser.add_argument('--base_branch', type=str, help='The base branch to compare against')
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