import argparse
import os
import robot
from glob import glob

def main(args):

    all_automation_files = ' '.join(glob("*.py") + glob("custom_functions/*.py"))
    
    print(all_automation_files)

    os.makedirs(args.output_dir, exist_ok=True)

    result = robot.run(
        args.robot_path,
        outputdir=args.output_dir,
        loglevel='DEBUG:INFO',
        variable=[f"FILES:{all_automation_files}"],
    )

    if result == 0:
        print("Tests passed successfully!")
    else:
        raise RuntimeError("Tests failed.")


if __name__ == "__main__":
    # Create the argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('--robot-path', type=str, help='Path of the robot test suite')
    parser.add_argument('--output-dir', type=str, help='Path to results')
 
    # Parse the arguments
    args = parser.parse_args()

    main(args=args)