import random
import string

from rygnal import rust_kernel


def generate_random_path() -> str:
    # Construct a random path with various characters to test parser boundaries
    components = []
    num_segments = random.randint(0, 5)

    # We want to randomly insert special elements
    choices = [
        "normal_dir",
        "normal_file.txt",
        "..",
        ".",
        "",
        "C:",
        "/absolute",
        "\\backslash",
        "with space",
        "\0",  # Null byte
        "secrets",
        "package.json",
        ".env",
    ]

    for _ in range(num_segments):
        choice = random.choice(choices)
        if choice == "normal_dir":
            # Generate random string
            components.append(
                "".join(random.choices(string.ascii_letters, k=random.randint(1, 10)))
            )
        else:
            components.append(choice)

    # Randomly join with slashes or backslashes
    joiner = random.choice(["/", "\\", "//"])
    return joiner.join(components)


def test_path_safety_fuzz_loop() -> None:
    # Run 1000 iterations of randomized paths to verify that path safety checkers
    # never raise unhandled exceptions and always return a valid, well-formed result.
    for _ in range(1000):
        path = generate_random_path()

        # Test validate_repo_relative_path
        res1 = rust_kernel.validate_repo_relative_path(path)
        assert isinstance(res1, dict)
        assert "safe" in res1
        assert "normalized_path" in res1
        assert "error_code" in res1
        assert "reason" in res1
        assert "is_sentinel" in res1

        if res1["safe"]:
            assert res1["error_code"] is None
            assert res1["reason"] is None
            assert res1["normalized_path"] is None or isinstance(res1["normalized_path"], str)
        else:
            assert isinstance(res1["error_code"], str)
            assert isinstance(res1["reason"], str)
            assert res1["normalized_path"] is None

        # Test validate_patch_path
        res2 = rust_kernel.validate_patch_path(path)
        assert isinstance(res2, dict)
        assert "safe" in res2
        assert "normalized_path" in res2
        assert "error_code" in res2
        assert "reason" in res2
        assert "is_sentinel" in res2

        if res2["safe"]:
            assert res2["error_code"] is None
            assert res2["reason"] is None
            assert res2["normalized_path"] is None or isinstance(res2["normalized_path"], str)
        else:
            assert isinstance(res2["error_code"], str)
            assert isinstance(res2["reason"], str)
            assert res2["normalized_path"] is None
