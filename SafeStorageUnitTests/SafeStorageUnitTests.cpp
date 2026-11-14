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

    TEST_METHOD(RegisterCreatesUserAndRejectsDuplicates)
    {
        const char username[] = "RegAa";
        const char password[] = "PassWord1@";
        NTSTATUS status;

        // Keep the test independent of execution order (earlier failures may
        // leave a session behind while store/retrieve are still stubs).
        (void)SafeStorageHandleLogout();

        status = SafeStorageHandleRegister(
            username, static_cast<uint16_t>(strlen(username)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        Assert::IsTrue(std::filesystem::is_directory(".\\users\\RegAa"));

        std::ifstream usersFile(".\\users.txt");
        std::string line;
        bool found = false;
        while (std::getline(usersFile, line))
        {
            if (line.rfind("RegAa:", 0) == 0)
            {
                found = true;
            }
            Assert::IsTrue(line.find(password) == std::string::npos);
        }
        Assert::IsTrue(found);

        // Same case and different case are both collisions on NTFS.
        status = SafeStorageHandleRegister(
            username, static_cast<uint16_t>(strlen(username)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsFalse(NT_SUCCESS(status));
        status = SafeStorageHandleRegister(
            "regaa", 5, password, static_cast<uint16_t>(strlen(password)));
        Assert::IsFalse(NT_SUCCESS(status));

        // Invalid username fails before creating anything.
        status = SafeStorageHandleRegister(
            "Al", 2, password, static_cast<uint16_t>(strlen(password)));
        Assert::IsFalse(NT_SUCCESS(status));
        Assert::IsFalse(std::filesystem::exists(".\\users\\Al"));

        // Register is unavailable while a user is logged in.
        EnterCriticalSection(&g_ss.StateLock);
        SsSessionSetLocked("UserA");
        LeaveCriticalSection(&g_ss.StateLock);
        status = SafeStorageHandleRegister(
            "RegBb", 5, password, static_cast<uint16_t>(strlen(password)));
        Assert::IsFalse(NT_SUCCESS(status));
        Assert::IsFalse(std::filesystem::exists(".\\users\\RegBb"));
        Assert::IsTrue(NT_SUCCESS(SafeStorageHandleLogout()));
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

    TEST_METHOD(StoreRetrieveRoundTripAndIsolation)
    {
        const char userA[] = "StorA";
        const char userB[] = "StorB";
        const char password[] = "PassWord1@";
        const char submission[] = "Report";
        const char sourceFile[] = ".\\stor_src.bin";
        const char destFile[] = ".\\stor_dst.bin";
        const size_t payloadSize = 1024 * 1024 + 123; // > several 64 KiB chunks
        NTSTATUS status;

        (void)SafeStorageHandleLogout();
        std::filesystem::remove(sourceFile);
        std::filesystem::remove(destFile);

        {
            std::ofstream out(sourceFile, std::ios::binary);
            for (size_t i = 0; i < payloadSize; i++)
            {
                out.put(static_cast<char>((i * 31u + 7u) & 0xFFu));
            }
        }

        status = SafeStorageHandleRegister(
            userA, static_cast<uint16_t>(strlen(userA)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));
        status = SafeStorageHandleRegister(
            userB, static_cast<uint16_t>(strlen(userB)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleLogin(
            userA, static_cast<uint16_t>(strlen(userA)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleStore(
            submission, static_cast<uint16_t>(strlen(submission)),
            sourceFile, static_cast<uint16_t>(strlen(sourceFile)));
        Assert::IsTrue(NT_SUCCESS(status));
        Assert::IsTrue(std::filesystem::is_regular_file(
            ".\\users\\StorA\\Report"));

        status = SafeStorageHandleRetrieve(
            submission, static_cast<uint16_t>(strlen(submission)),
            destFile, static_cast<uint16_t>(strlen(destFile)));
        Assert::IsTrue(NT_SUCCESS(status));
        Assert::IsTrue(std::filesystem::file_size(sourceFile) ==
                       std::filesystem::file_size(destFile));

        {
            std::ifstream inA(sourceFile, std::ios::binary);
            std::ifstream inB(destFile, std::ios::binary);
            std::vector<char> bytesA((std::istreambuf_iterator<char>(inA)),
                                     std::istreambuf_iterator<char>());
            std::vector<char> bytesB((std::istreambuf_iterator<char>(inB)),
                                     std::istreambuf_iterator<char>());
            Assert::IsTrue(bytesA == bytesB);
        }

        Assert::IsTrue(NT_SUCCESS(SafeStorageHandleLogout()));

        // Cross-user isolation: B cannot retrieve A's file, cannot use A's
        // directory as a store source, and cannot read the credential DB.
        status = SafeStorageHandleLogin(
            userB, static_cast<uint16_t>(strlen(userB)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleRetrieve(
            submission, static_cast<uint16_t>(strlen(submission)),
            destFile, static_cast<uint16_t>(strlen(destFile)));
        Assert::IsFalse(NT_SUCCESS(status));

        status = SafeStorageHandleStore(
            "Stolen", 6,
            ".\\users\\StorA\\Report",
            static_cast<uint16_t>(strlen(".\\users\\StorA\\Report")));
        Assert::IsFalse(NT_SUCCESS(status));

        status = SafeStorageHandleStore(
            "Hashes", 6,
            ".\\users.txt",
            static_cast<uint16_t>(strlen(".\\users.txt")));
        Assert::IsFalse(NT_SUCCESS(status));

        Assert::IsTrue(NT_SUCCESS(SafeStorageHandleLogout()));

        // A cannot overwrite the DB, another user's directory, or use path
        // aliases; ordinary destinations in %AppDir% remain allowed.
        status = SafeStorageHandleLogin(
            userA, static_cast<uint16_t>(strlen(userA)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleRetrieve(
            submission, static_cast<uint16_t>(strlen(submission)),
            ".\\users.txt",
            static_cast<uint16_t>(strlen(".\\users.txt")));
        Assert::IsFalse(NT_SUCCESS(status));
        status = SafeStorageHandleRetrieve(
            submission, static_cast<uint16_t>(strlen(submission)),
            ".\\users\\StorA\\x",
            static_cast<uint16_t>(strlen(".\\users\\StorA\\x")));
        Assert::IsFalse(NT_SUCCESS(status));
        status = SafeStorageHandleRetrieve(
            submission, static_cast<uint16_t>(strlen(submission)),
            ".\\users.txt.",
            static_cast<uint16_t>(strlen(".\\users.txt.")));
        Assert::IsFalse(NT_SUCCESS(status));
        status = SafeStorageHandleRetrieve(
            submission, static_cast<uint16_t>(strlen(submission)),
            ".\\dummyData",
            static_cast<uint16_t>(strlen(".\\dummyData")));
        Assert::IsTrue(NT_SUCCESS(status));

        Assert::IsTrue(NT_SUCCESS(SafeStorageHandleLogout()));

        std::filesystem::remove(sourceFile);
        std::filesystem::remove(destFile);
    };

    TEST_METHOD(TransferEdgeCases)
    {
        const char user[] = "EdgeA";
        const char password[] = "PassWord1@";
        const char submission[] = "Empty";
        const char source[] = ".\\edge_src.bin";
        const char dest[] = ".\\edge_dst.bin";
        NTSTATUS status;

        (void)SafeStorageHandleLogout();
        EnterCriticalSection(&g_ss.StateLock);
        SsRateLimiterResetLocked();
        LeaveCriticalSection(&g_ss.StateLock);

        status = SafeStorageHandleRegister(
            user, static_cast<uint16_t>(strlen(user)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        // store/retrieve are unavailable while logged out.
        status = SafeStorageHandleStore(
            submission, static_cast<uint16_t>(strlen(submission)),
            source, static_cast<uint16_t>(strlen(source)));
        Assert::IsFalse(NT_SUCCESS(status));

        status = SafeStorageHandleLogin(
            user, static_cast<uint16_t>(strlen(user)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        // 0-byte file.
        {
            std::ofstream empty(source, std::ios::binary);
        }
        status = SafeStorageHandleStore(
            submission, static_cast<uint16_t>(strlen(submission)),
            source, static_cast<uint16_t>(strlen(source)));
        Assert::IsTrue(NT_SUCCESS(status));
        status = SafeStorageHandleRetrieve(
            submission, static_cast<uint16_t>(strlen(submission)),
            dest, static_cast<uint16_t>(strlen(dest)));
        Assert::IsTrue(NT_SUCCESS(status));
        Assert::IsTrue(std::filesystem::file_size(dest) == 0);

        // 1-byte file overwrites the submission.
        {
            std::ofstream one(source, std::ios::binary);
            one.put('Z');
        }
        status = SafeStorageHandleStore(
            submission, static_cast<uint16_t>(strlen(submission)),
            source, static_cast<uint16_t>(strlen(source)));
        Assert::IsTrue(NT_SUCCESS(status));

        // Overwrite an existing destination.
        {
            std::ofstream old(dest, std::ios::binary);
            old << "old-content-that-must-disappear";
        }
        status = SafeStorageHandleRetrieve(
            submission, static_cast<uint16_t>(strlen(submission)),
            dest, static_cast<uint16_t>(strlen(dest)));
        Assert::IsTrue(NT_SUCCESS(status));
        Assert::IsTrue(std::filesystem::file_size(dest) == 1);
        {
            std::ifstream in(dest, std::ios::binary);
            char c = 0;
            in.get(c);
            Assert::IsTrue(c == 'Z');
        }

        // Missing source and missing submission fail without partial output.
        status = SafeStorageHandleStore(
            "Missing", 7,
            ".\\does_not_exist.bin",
            static_cast<uint16_t>(strlen(".\\does_not_exist.bin")));
        Assert::IsFalse(NT_SUCCESS(status));
        std::filesystem::remove(".\\edge_missing.bin");
        status = SafeStorageHandleRetrieve(
            "NoSuchFile", 10,
            ".\\edge_missing.bin",
            static_cast<uint16_t>(strlen(".\\edge_missing.bin")));
        Assert::IsFalse(NT_SUCCESS(status));
        Assert::IsFalse(std::filesystem::exists(".\\edge_missing.bin"));

        // Traversal submission name is rejected.
        status = SafeStorageHandleStore(
            "..\\escape", 9, source, static_cast<uint16_t>(strlen(source)));
        Assert::IsFalse(NT_SUCCESS(status));

        Assert::IsTrue(NT_SUCCESS(SafeStorageHandleLogout()));

        // No transfer temp files may leak into the user directory or cwd.
        for (const auto& entry : std::filesystem::directory_iterator(".\\users\\EdgeA"))
        {
            const std::string name = entry.path().filename().string();
            Assert::IsFalse(name.rfind(".sstmp_", 0) == 0);
        }
        for (const auto& entry : std::filesystem::directory_iterator("."))
        {
            const std::string name = entry.path().filename().string();
            Assert::IsFalse(name.rfind(".ssdl_", 0) == 0);
        }

        std::filesystem::remove(source);
        std::filesystem::remove(dest);
    };

    TEST_METHOD(RejectsOverEightGiB)
    {
        const char* runLarge = std::getenv("SS_RUN_LARGE_TESTS");
        if (runLarge == nullptr)
        {
            Logger::WriteMessage("RejectsOverEightGiB skipped: set SS_RUN_LARGE_TESTS=1");
            return;
        }

        const char user[] = "HugeA";
        const char password[] = "PassWord1@";
        const char source[] = ".\\huge_sparse.bin";
        NTSTATUS status;
        HANDLE file;
        DWORD returned = 0;
        LARGE_INTEGER size;

        (void)SafeStorageHandleLogout();
        std::filesystem::remove(source);

        file = CreateFileA(source, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
        Assert::IsTrue(file != INVALID_HANDLE_VALUE);
        (void)DeviceIoControl(file, FSCTL_SET_SPARSE, NULL, 0,
                              NULL, 0, &returned, NULL);
        size.QuadPart = static_cast<LONGLONG>(SS_MAX_FILE_SIZE + 1);
        Assert::IsTrue(SetFilePointerEx(file, size, NULL, FILE_BEGIN) != 0);
        Assert::IsTrue(SetEndOfFile(file) != 0);
        CloseHandle(file);

        status = SafeStorageHandleRegister(
            user, static_cast<uint16_t>(strlen(user)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));
        status = SafeStorageHandleLogin(
            user, static_cast<uint16_t>(strlen(user)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleStore(
            "Huge", 4, source, static_cast<uint16_t>(strlen(source)));
        Assert::IsFalse(NT_SUCCESS(status));
        Assert::IsFalse(std::filesystem::exists(".\\users\\HugeA\\Huge"));

        Assert::IsTrue(NT_SUCCESS(SafeStorageHandleLogout()));
        std::filesystem::remove(source);
    };

    TEST_METHOD(FuzzValidationAndPaths)
    {
        std::mt19937 rng(0xC0FFEEu);
        char path[MAX_PATH];

        for (int i = 0; i < 4000; i++)
        {
            const size_t len = rng() % 300;
            std::string data(len, '\0');
            for (size_t j = 0; j < len; j++)
            {
                data[j] = static_cast<char>(rng() % 256);
            }

            (void)SsValidateUsername(data.data(),
                                     static_cast<uint16_t>(len));
            (void)SsValidatePassword(data.data(),
                                     static_cast<uint16_t>(len));
            (void)SsValidateSubmissionName(data.data(),
                                            static_cast<uint16_t>(len));
            (void)SsCanonicalizeUserPath(data.data(),
                                         static_cast<uint16_t>(len),
                                         path, sizeof(path));
        }

        // NULL / zero-length API inputs must fail, never crash.
        Assert::IsFalse(NT_SUCCESS(SafeStorageHandleRegister(nullptr, 0, nullptr, 0)));
        Assert::IsFalse(NT_SUCCESS(SafeStorageHandleLogin(nullptr, 0, nullptr, 0)));
        Assert::IsFalse(NT_SUCCESS(SafeStorageHandleStore(nullptr, 0, nullptr, 0)));
        Assert::IsFalse(NT_SUCCESS(SafeStorageHandleRetrieve(nullptr, 0, nullptr, 0)));
    };

    TEST_METHOD(LoginAndBruteForce)
    {
        const char username[] = "LogAa";
        const char password[] = "PassWord1@";
        const char wrong[] = "WrongPass1@";
        NTSTATUS status;
        NTSTATUS unknownStatus;
        NTSTATUS wrongStatus;

        (void)SafeStorageHandleLogout();
        EnterCriticalSection(&g_ss.StateLock);
        SsRateLimiterResetLocked();
        LeaveCriticalSection(&g_ss.StateLock);

        status = SafeStorageHandleRegister(
            username, static_cast<uint16_t>(strlen(username)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        status = SafeStorageHandleLogin(
            username, static_cast<uint16_t>(strlen(username)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));

        // A second login while logged in must fail and keep the session.
        status = SafeStorageHandleLogin(
            username, static_cast<uint16_t>(strlen(username)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsFalse(NT_SUCCESS(status));
        Assert::IsTrue(SsSessionIsLoggedIn());
        Assert::IsTrue(NT_SUCCESS(SafeStorageHandleLogout()));

        // Five failures saturate the global window; the sixth (correct) is
        // rejected too, as required by the assignment.
        for (int i = 0; i < static_cast<int>(SS_MAX_LOGIN_FAILURES); i++)
        {
            status = SafeStorageHandleLogin(
                username, static_cast<uint16_t>(strlen(username)),
                wrong, static_cast<uint16_t>(strlen(wrong)));
            Assert::IsFalse(NT_SUCCESS(status));
        }

        status = SafeStorageHandleLogin(
            username, static_cast<uint16_t>(strlen(username)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsFalse(NT_SUCCESS(status));
        Assert::IsFalse(SsSessionIsLoggedIn());

        std::this_thread::sleep_for(
            std::chrono::milliseconds(SS_LOGIN_WINDOW_MS + 100));

        status = SafeStorageHandleLogin(
            username, static_cast<uint16_t>(strlen(username)),
            password, static_cast<uint16_t>(strlen(password)));
        Assert::IsTrue(NT_SUCCESS(status));
        Assert::IsTrue(NT_SUCCESS(SafeStorageHandleLogout()));

        // Unknown user and wrong password are indistinguishable to the caller.
        unknownStatus = SafeStorageHandleLogin(
            "Zzzzz", static_cast<uint16_t>(strlen("Zzzzz")),
            password, static_cast<uint16_t>(strlen(password)));
        wrongStatus = SafeStorageHandleLogin(
            username, static_cast<uint16_t>(strlen(username)),
            wrong, static_cast<uint16_t>(strlen(wrong)));
        Assert::IsTrue(unknownStatus == wrongStatus);
        Assert::IsFalse(NT_SUCCESS(unknownStatus));

        // Leave the global limiter clean for the rest of the suite.
        std::this_thread::sleep_for(
            std::chrono::milliseconds(SS_LOGIN_WINDOW_MS + 100));
    };

    TEST_METHOD(SessionAndRateLimiter)
    {
        char username[SS_USERNAME_MAX + 1];
        NTSTATUS status;

        (void)SafeStorageHandleLogout();

        // Logged out after the defensive logout above.
        Assert::IsFalse(SsSessionIsLoggedIn());
        Assert::IsFalse(NT_SUCCESS(SsSessionLogout()));
        Assert::IsFalse(NT_SUCCESS(SsSessionCopyUsername(username, sizeof(username))));

        EnterCriticalSection(&g_ss.StateLock);
        SsSessionSetLocked("UserA");
        LeaveCriticalSection(&g_ss.StateLock);

        Assert::IsTrue(SsSessionIsLoggedIn());
        status = SsSessionCopyUsername(username, sizeof(username));
        Assert::IsTrue(NT_SUCCESS(status));
        Assert::IsTrue(std::string(username) == "UserA");

        status = SsSessionLogout();
        Assert::IsTrue(NT_SUCCESS(status));
        Assert::IsFalse(SsSessionIsLoggedIn());
        Assert::IsFalse(NT_SUCCESS(SsSessionLogout()));

        // Global limiter: five failures block, and the window expires.
        EnterCriticalSection(&g_ss.StateLock);
        SsRateLimiterResetLocked();
        for (int i = 0; i < static_cast<int>(SS_MAX_LOGIN_FAILURES); i++)
        {
            Assert::IsFalse(SsRateLimiterCheckLocked());
            SsRateLimiterRecordFailureLocked();
        }
        Assert::IsTrue(SsRateLimiterCheckLocked());
        LeaveCriticalSection(&g_ss.StateLock);

        std::this_thread::sleep_for(std::chrono::milliseconds(SS_LOGIN_WINDOW_MS + 100));

        EnterCriticalSection(&g_ss.StateLock);
        Assert::IsFalse(SsRateLimiterCheckLocked());
        SsRateLimiterResetLocked();
        LeaveCriticalSection(&g_ss.StateLock);
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
        Assert::IsFalse(NT_SUCCESS(SsCanonicalizeUserPath(
            "\\\\server\\share\\x",
            static_cast<uint16_t>(strlen("\\\\server\\share\\x")),
            out, MAX_PATH)));
        Assert::IsFalse(NT_SUCCESS(SsCanonicalizeUserPath(
            "\\\\.\\C:\\x", 8, out, MAX_PATH)));
        Assert::IsFalse(NT_SUCCESS(SsCanonicalizeUserPath(
            ".\\CON", 5, out, MAX_PATH)));
        Assert::IsFalse(NT_SUCCESS(SsCanonicalizeUserPath(
            ".\\x.", 4, out, MAX_PATH)));
        Assert::IsFalse(NT_SUCCESS(SsCanonicalizeUserPath(
            ".\\x ", 4, out, MAX_PATH)));
        Assert::IsTrue(SsIsTempFileName(".sstmp_abc"));
        Assert::IsTrue(SsIsTempFileName("C:\\tmp\\.ssdl_abc"));
        Assert::IsFalse(SsIsTempFileName("C:\\tmp\\normal.txt"));

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