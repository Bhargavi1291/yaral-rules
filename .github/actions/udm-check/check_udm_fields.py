import re
import sys
 
def validate_yara_rule(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
 
    # Find all conditions using '!=' in the events section
    conditions = re.findall(r'\$(.*?)\s*!=\s*"(.*?)"', content)
 
    missing_conditions = []
 
    for condition in conditions:
        field, value = condition
        # Check if the field has a corresponding != "" condition
        if f'{field} != ""' not in content:
            missing_conditions.append(field)
 
    if missing_conditions:
        print(f"Error: The following fields are missing `!= \"\"` conditions: {', '.join(missing_conditions)}")
        return False
    else:
        print("All conditions are properly checked.")
        return True
 
if __name__ == "__main__":
    file_path = sys.argv[1]
    if not validate_yara_rule(file_path):
        sys.exit(1)  # Exit with error if validation fails
