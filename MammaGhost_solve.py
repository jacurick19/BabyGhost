# This script will generate a file to solve mammaGhost

offset = 0 #calculate by subtracting the given size_t values
with open("nums.txt", "w") as f:
    for i in range(48):
        for j in range(10):
            f.write("1\n")
        f.write(str(offset) + "\n")
        offset += 1
        f.write("0\n")
