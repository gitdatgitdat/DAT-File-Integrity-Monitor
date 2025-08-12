import Main.core as core
print("Imported module:", core.__file__)
print("Has hash_file:", hasattr(core, "hash_file"))

# If True, run it:
if hasattr(core, "hash_file"):
    print(core.hash_file("Test/sample.txt"))
    print(core.hash_file("Test/sample.txt", algo="md5"))