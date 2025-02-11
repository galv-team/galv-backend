import os
import sys

if len(sys.argv) < 3:
    print("Usage: find_prev_tag.py <tags.txt file> <clean_version string>")
    sys.exit(1)

# Parse args
tags_file = sys.argv[1]
my_clean_version = sys.argv[2]

with open(tags_file, "r") as f:
    tags = f.read().splitlines()

if my_clean_version not in tags:
    print(f"Appending {my_clean_version} to tag list")
    tags.append(my_clean_version)


# split into major, minor, patch, note and sort by each part
def major(s):
    return int(s.split(".")[0][1:])  # strip 'v' prefix for major


def minor(s):
    return int(s.split(".")[1])


def patch(s):
    return int(s.split(".")[2].split("-")[0])


tags.sort(key=lambda s: (major(s), minor(s), patch(s)))

i = tags.index(my_clean_version)

# Determine if we're the latest tag
if i == len(tags) - 1:
    print(f"{my_clean_version} is the latest version.")
    os.system("echo IS_LATEST=true >> $GITHUB_OUTPUT")
else:
    os.system("echo IS_LATEST=false >> $GITHUB_OUTPUT")

if i == 0:
    print(
        f"{my_clean_version} is the first tag, no previous version or previous major version."
    )
    os.system("echo PREVIOUS_VERSION= >> $GITHUB_OUTPUT")
    os.system("echo PREVIOUS_MAJOR_VERSION= >> $GITHUB_OUTPUT")
else:
    os.system(f"echo PREVIOUS_VERSION={tags[i - 1]} >> $GITHUB_OUTPUT")
    print(f"Previous version: {tags[i - 1]}")
    # Get the previous major version tag
    major_version = tags[i].split(".")[0]
    prev_ver_tags = [tag for tag in tags if tag.split(".")[0] < major_version]
    if len(prev_ver_tags) == 0:
        print(f"{major_version} is the first major version, no previous major version.")
        os.system("echo PREVIOUS_MAJOR_VERSION= >> $GITHUB_OUTPUT")
    else:
        os.system(f"echo PREVIOUS_MAJOR_VERSION={prev_ver_tags[-1]} >> $GITHUB_OUTPUT")
        print(f"Previous major version: {prev_ver_tags[-1]}")
