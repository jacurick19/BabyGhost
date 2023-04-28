offset = 0 #Construct by subtracting the given values
with open("nums.txt", "w") as f:
    for i in range(40):
        for j in range(128):
            for k in range(10):
                f.write("1\n")
            f.write(str(offset) + "\n")
            f.write(str(j) + "\n")
        offset += 1
