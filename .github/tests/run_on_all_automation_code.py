import argparse
import robot
from glob import glob

def main(args):

    all_automation_files = ' '.join(glob("*.py") + glob("custom_functions/*.py"))
    
    print(all_automation_files)

    result = robot.run(
        args.robot_path,
        outputdir='results',
        loglevel='DEBUG:INFO',
        variable=[f"FILES:{all_automation_files}"]
    )

    if result == 0:
        print("Tests passed successfully!")
    else:
        print("Tests failed.")


if __name__ == "__main__":
    # Create the argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('--robot-path', type=str, help='Path of the robot test suite')
 
    # Parse the arguments
    args = parser.parse_args()

    main(args=args)