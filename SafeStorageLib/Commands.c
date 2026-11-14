#include "Commands.h"

#define APPDATA_LOCAL_DIR_PATH "~"
#define APP_NAME "SafeStorage"


NTSTATUS WINAPI
SafeStorageInit(
    VOID
)
{
    // Finding the AppData directory and forfirming or creting the SafeStorage folder
    FILE* app_data_dir = fopen(APPDATA_LOCAL_DIR_PATH, "r");
    printf("starting\n");
    if (app_data_dir) {
        int no_chars = strlen(APPDATA_LOCAL_DIR_PATH + strlen(APP_NAME) + 2;
        printf("no chars: %d\n", no_chars);
        char* application_dir_path = malloc(no_chars);
        application_dir_path[0] = '\0';
        strcat(application_dir_path, APPDATA_LOCAL_DIR_PATH);
        int l = strlen(application_dir_path);
        application_dir_path[l] = '\\';
        application_dir_path[l + 1] = '\0';
        strcat(application_dir_path, APP_NAME);
        printf("%s\n", application_dir_path);
        FILE* application_dir = fopen(application_dir_path, "r");

        if (application_dir) {
            printf("reached\n");
            fclose(application_dir);
        }

        fclose(app_data_dir);
        free(application_dir_path);
    }
    return STATUS_SUCCESS;
}


VOID WINAPI
SafeStorageDeinit(
    VOID
)
{
    /* The function is not implemented. It is your responsibility. */
    /* Here you can clean up any global objects you have created earlier. */

    return;
}


NTSTATUS WINAPI
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(UsernameLength);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PasswordLength);

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(UsernameLength);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PasswordLength);

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    /* The function is not implemented. It is your responsibility. */

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleStore(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* SourceFilePath,
    uint16_t SourceFilePathLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(SourceFilePath);
    UNREFERENCED_PARAMETER(SourceFilePathLength);

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* DestinationFilePath,
    uint16_t DestinationFilePathLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(DestinationFilePath);
    UNREFERENCED_PARAMETER(DestinationFilePathLength);

    return STATUS_NOT_IMPLEMENTED;
}
