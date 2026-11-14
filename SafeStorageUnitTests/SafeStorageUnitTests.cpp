#include "test_includes.hpp"


/**
 * @brief	In this file you can add unit tests for the functionality.
 *          Only for unit tests here you are free to use c++ and any std library.
 */
namespace SafeStorageUnitTests
{

TEST_MODULE_INITIALIZE(UserActivityTestInit)
{
    // Ensure we cleanup any pre-existing files.
    if (std::filesystem::is_regular_file(".\\users.txt"))
    {
        std::filesystem::remove(".\\users.txt");
    }
    if (std::filesystem::is_directory(".\\users"))
    {
        std::filesystem::remove_all(".\\users");
    }
    
    Assert::IsTrue(NT_SUCCESS(SafeStorageInit()));
};
TEST_MODULE_CLEANUP(UserActivityTestUninit)
{
    SafeStorageDeinit();
};

TEST_CLASS(UserActivityTest)
{
    TEST_METHOD(UserRegisterLoginLogout)
    {
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        const char username[] = "UserA";
        const char password[] = "PassWord1@";

        status = SafeStorageHandleRegister(username,
                                           static_cast<uint16_t>(strlen(username)),
                                           password,
                                           static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        //
        // As per requirements.
        // Registering a user requires the creation of the following:
        //  <current dir>           - %appdir% (application directory)
        //       |- users.txt       (file)
        //       |- users           (directory)
        //           |- UserA       (directory)
        //
        Assert::IsTrue(std::filesystem::is_regular_file(".\\users.txt"));
        Assert::IsTrue(std::filesystem::is_directory(".\\users"));
        Assert::IsTrue(std::filesystem::is_directory(".\\users\\UserA"));

        status = SafeStorageHandleLogin(username,
                                        static_cast<uint16_t>(strlen(username)),
                                        password,
                                        static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleLogout();
        Assert::IsTrue(NT_SUCCESS(status));
    };

    TEST_METHOD(FileTransfer)
    {
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        const char username[] = "UserB";
        const char password[] = "PassWord1@";

        const char submissionName[] = "Homework";
        const char submissionFilePath[] = ".\\dummyData";

        // Drop dummy data for transfer test
        {
            std::ofstream transferFileTest(submissionFilePath);
            transferFileTest << "This is a dummy content";
        }

        status = SafeStorageHandleRegister(username,
                                           static_cast<uint16_t>(strlen(username)),
                                           password,
                                           static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleLogin(username,
                                        static_cast<uint16_t>(strlen(username)),
                                        password,
                                        static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleStore(submissionName,
                                        static_cast<uint16_t>(strlen(submissionName)),
                                        submissionFilePath,
                                        static_cast<uint16_t>(strlen(submissionFilePath)));
        Assert::IsTrue(NT_SUCCESS(status));

        //
        // As per requirements; a file called "Homework"
        // must be created under the users directory.
        //
        // The file must have the same content as the copied file.
        //
        Assert::IsTrue(std::filesystem::is_regular_file(".\\users\\UserB\\Homework"));
        Assert::IsTrue(std::filesystem::file_size(submissionFilePath) ==
                       std::filesystem::file_size(".\\users\\UserB\\Homework"));
        status = SafeStorageHandleRetrieve(submissionName,
                                           static_cast<uint16_t>(strlen(submissionName)),
                                           submissionFilePath,
                                           static_cast<uint16_t>(strlen(submissionFilePath)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleLogout();
        Assert::IsTrue(NT_SUCCESS(status));
    };

    TEST_METHOD(InitCreatesRequiredResources)
    {
        Assert::IsTrue(std::filesystem::is_directory(".\\users"));
        Assert::IsTrue(std::filesystem::is_regular_file(".\\users.txt"));
    };

    TEST_METHOD(CredentialStoreHashesAndVerifies)
    {
        const char usernameA[] = "CredA";
        const char usernameB[] = "CredB";
        const char password[] = "PassWord1@";
        BOOL exists = FALSE;
        BOOL match = FALSE;
        NTSTATUS status;

        status = SsUserAdd(usernameA, password,
                           static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));
        status = SsUserAdd(usernameB, password,
                           static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SsUserExists(usernameA, &exists);
        Assert::IsTrue(NT_SUCCESS(status));
        Assert::IsTrue(exists);

        status = SsUserVerify(usernameA, password,
                              static_cast<uint16_t>(strlen(password)), &match);
        Assert::IsTrue(NT_SUCCESS(status));
        Assert::IsTrue(match);

        status = SsUserVerify(usernameA, "WrongPass1@",
                              static_cast<uint16_t>(strlen("WrongPass1@")), &match);
        Assert::IsTrue(NT_SUCCESS(status));
        Assert::IsFalse(match);

        // Unknown user follows the same success/`Match=false` contract.
        status = SsUserVerify("Zzzzz", password,
                              static_cast<uint16_t>(strlen(password)), &match);
        Assert::IsTrue(NT_SUCCESS(status));
        Assert::IsFalse(match);

        // Case-insensitive duplicate must be rejected.
        status = SsUserAdd("creda", password,
                           static_cast<uint16_t>(strlen(password)));
        Assert::IsFalse(NT_SUCCESS(status));

        std::ifstream usersFile(".\\users.txt");
        std::string line;
        std::string lineA;
        std::string lineB;
        size_t countA = 0;

        while (std::getline(usersFile, line))
        {
            if (line.rfind("CredA:", 0) == 0)
            {
                lineA = line;
                countA++;
            }
            else if (line.rfind("CredB:", 0) == 0)
            {
                lineB = line;
            }
            Assert::IsTrue(line.find(password) == std::string::npos);
        }

        Assert::IsTrue(countA == 1);
        Assert::IsFalse(lineA.empty());
        Assert::IsFalse(lineB.empty());
        Assert::IsTrue(lineA != lineB); // different salts -> different hashes
    };

    TEST_METHOD(ValidationRejectsMaliciousInput)
    {
        char out[MAX_PATH];
        char badDevicePath[] = "\\\\?\\C:\\x";
        char badDriveRelative[] = "C:x";
        char badAds[] = "a:b";
        char badTrailingDot[] = ".\\users.txt.";

        // Usernames: 5-10 ASCII letters only.
        Assert::IsTrue(NT_SUCCESS(SsValidateUsername("UserA", 5)));
        Assert::IsFalse(NT_SUCCESS(SsValidateUsername("Al", 2)));
        Assert::IsFalse(NT_SUCCESS(SsValidateUsername("Alice1", 6)));
        Assert::IsFalse(NT_SUCCESS(SsValidateUsername("Ali ce", 6)));

        // Passwords: length 5-128, one of each class, strict allow-list.
        Assert::IsTrue(NT_SUCCESS(SsValidatePassword("PassWord1@", 10)));
        Assert::IsFalse(NT_SUCCESS(SsValidatePassword("password1@", 10)));
        Assert::IsFalse(NT_SUCCESS(SsValidatePassword("PASSWORD1@", 10)));
        Assert::IsFalse(NT_SUCCESS(SsValidatePassword("PassWord@", 9)));
        Assert::IsFalse(NT_SUCCESS(SsValidatePassword("PassWord1", 9)));
        Assert::IsFalse(NT_SUCCESS(SsValidatePassword("Pass Word1@", 11)));

        // Submission names: safe basename, no reserved devices.
        Assert::IsTrue(NT_SUCCESS(SsValidateSubmissionName("Homework", 8)));
        Assert::IsTrue(NT_SUCCESS(SsValidateSubmissionName("hw_1.final", 10)));
        Assert::IsFalse(NT_SUCCESS(SsValidateSubmissionName("..\\users.txt", 12)));
        Assert::IsFalse(NT_SUCCESS(SsValidateSubmissionName("CON", 3)));
        Assert::IsFalse(NT_SUCCESS(SsValidateSubmissionName("con.txt", 7)));
        Assert::IsFalse(NT_SUCCESS(SsValidateSubmissionName("x.", 2)));
        Assert::IsFalse(NT_SUCCESS(SsValidateSubmissionName("a:b", 3)));

        // Path canonicalization: reject device/ADS/trailing-dot forms.
        Assert::IsTrue(NT_SUCCESS(SsCanonicalizeUserPath(
            ".\\dummyData", 11, out, MAX_PATH)));
        Assert::IsTrue(out[1] == ':');
        Assert::IsFalse(NT_SUCCESS(SsCanonicalizeUserPath(
            badDevicePath, static_cast<uint16_t>(strlen(badDevicePath)),
            out, MAX_PATH)));
        Assert::IsFalse(NT_SUCCESS(SsCanonicalizeUserPath(
            badDriveRelative, static_cast<uint16_t>(strlen(badDriveRelative)),
            out, MAX_PATH)));
        Assert::IsFalse(NT_SUCCESS(SsCanonicalizeUserPath(
            badAds, static_cast<uint16_t>(strlen(badAds)),
            out, MAX_PATH)));
        Assert::IsFalse(NT_SUCCESS(SsCanonicalizeUserPath(
            badTrailingDot, static_cast<uint16_t>(strlen(badTrailingDot)),
            out, MAX_PATH)));

        // Component-boundary containment.
        Assert::IsTrue(SsIsPathInside(
            "C:\\App\\users\\Alex\\Homework",
            "C:\\App\\users\\Alex"));
        Assert::IsTrue(SsIsPathInside(
            "C:\\App\\users\\Alex",
            "C:\\App\\users\\Alex"));
        Assert::IsFalse(SsIsPathInside(
            "C:\\App\\users\\Alex2",
            "C:\\App\\users\\Alex"));
        Assert::IsTrue(SsIsPathInside(
            "C:\\App\\users\\Alex",
            "C:\\App\\users"));
        Assert::IsFalse(SsIsPathInside(
            "C:\\App\\users\\Alex",
            "C:\\App\\users2"));
    };
};
};