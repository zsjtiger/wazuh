/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef WIN32

#include "shared.h"
#include "list_op.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"
#include "execd.h"
#include "active-response/active_responses.h"

#ifdef WAZUH_UNIT_TESTING
    #include "unit_tests/wrappers/windows/libc/stdio_wrappers.h"
#endif

#ifdef ARGV0
#undef ARGV0
#endif

#define ARGV0 "wazuh-modulesd"
extern w_queue_t * winexec_queue;

/* Timeout list */
OSList *timeout_list;
OSListNode *timeout_node;

void win_timeout_run() {
    time_t curr_time = time(NULL);

    if (timeout_list) {
        /* Check if there is any timed out command to execute */
        timeout_node = OSList_GetFirstNode(timeout_list);
        while (timeout_node) {
            timeout_data *list_entry;

            list_entry = (timeout_data *)timeout_node->data;

            /* Timed out */
            if ((curr_time - list_entry->time_of_addition) > list_entry->time_to_block) {

                mtdebug1(WM_EXECD_LOGTAG, "Executing command '%s %s' after a timeout of '%ds'",
                    list_entry->command[0],
                    list_entry->parameters ? list_entry->parameters : "",
                    list_entry->time_to_block
                );

                wfd_t *wfd = wpopenv(list_entry->command[0], list_entry->command, W_BIND_STDIN);
                if (wfd) {
                    fwrite(list_entry->parameters, 1, strlen(list_entry->parameters), wfd->file);
                    wpclose(wfd);
                } else {
                    mterror(WM_EXECD_LOGTAG, EXEC_CMD_FAIL, strerror(errno), errno);
                }

                /* Delete currently node - already sets the pointer to next */
                OSList_DeleteCurrentlyNode(timeout_list);
                timeout_node = OSList_GetCurrentlyNode(timeout_list);

                /* Clear the memory */
                free_timeout_entry(list_entry);
            } else {
                timeout_node = OSList_GetNextNode(timeout_list);
            }
        }
    }
}

void win_execd_run(char *exec_msg)
{
    time_t curr_time;

    int timeout_value;
    int added_before = 0;

    cJSON *json_root = NULL;
    char *name = NULL;
    char *cmd[2] = { NULL, NULL };
    char *cmd_parameters = NULL;

    timeout_data *timeout_entry;

    /* Current time */
    curr_time = time(0);

    /* Parse message */
    if (json_root = cJSON_Parse(exec_msg), !json_root) {
        mterror(WM_EXECD_LOGTAG, EXEC_INV_JSON, exec_msg);
        return;
    }

    /* Get application name */
    cJSON *json_command = cJSON_GetObjectItem(json_root, "command");
    if (json_command && (json_command->type == cJSON_String)) {
        name = json_command->valuestring;
    } else {
        mterror(WM_EXECD_LOGTAG, EXEC_INV_CMD, exec_msg);
        cJSON_Delete(json_root);
        return;
    }

    /* Get command to execute */
    cmd[0] = get_command_by_name(name, &timeout_value);
    if (!cmd[0]) {
        read_exec_config();
        cmd[0] = get_command_by_name(name, &timeout_value);
        if (!cmd[0]) {
            mterror(WM_EXECD_LOGTAG, EXEC_INV_NAME, name);
            cJSON_Delete(json_root);
            return;
        }
    }
    if (cmd[0][0] == '\0') {
        cJSON_Delete(json_root);
        return;
    }

    /* Check if this command was already executed */
    timeout_node = OSList_GetFirstNode(timeout_list);
    added_before = 0;

    while (timeout_node) {
        timeout_data *list_entry;

        list_entry = (timeout_data *)timeout_node->data;
        if (strcmp(list_entry->command[0], cmd[0]) == 0) {
            /* Means we executed this command before and we don't need to add it again */
            added_before = 1;

            /* Update the timeout */
            mtdebug1(WM_EXECD_LOGTAG, "Command already received, updating time of addition to now.");
            list_entry->time_of_addition = curr_time;
            break;
        }

        /* Continue with the next entry in timeout list */
        timeout_node = OSList_GetNextNode(timeout_list);
    }

    /* If it wasn't added before, do it now */
    if (!added_before) {
        /* Command parameters */
        cJSON_ReplaceItemInObject(json_root, "command", cJSON_CreateString(ADD_ENTRY));
        cJSON *json_origin = cJSON_GetObjectItem(json_root, "origin");
        cJSON_ReplaceItemInObject(json_origin, "module", cJSON_CreateString(ARGV0));
        cJSON *json_parameters = cJSON_GetObjectItem(json_root, "parameters");
        cJSON_AddItemToObject(json_parameters, "program", cJSON_CreateString(cmd[0]));
        cmd_parameters = cJSON_PrintUnformatted(json_root);

        /* Execute command */
        mtdebug1(WM_EXECD_LOGTAG, "Executing command '%s %s'", cmd[0], cmd_parameters ? cmd_parameters : "");

        wfd_t *wfd = wpopenv(cmd[0], cmd, W_BIND_STDIN);
        if (wfd) {
            fwrite(cmd_parameters, 1, strlen(cmd_parameters), wfd->file);
            wpclose(wfd);
        } else {
            mterror(WM_EXECD_LOGTAG, EXEC_CMD_FAIL, strerror(errno), errno);
            os_free(cmd_parameters);
            cJSON_Delete(json_root);
            return;
        }

        /* Set rkey initially with the name of the AR */
        memset(rkey, '\0', OS_SIZE_4096);
        snprintf(rkey, OS_SIZE_4096 - 1, "%s", basename_ex(cmd[0]));

        keys_json = get_json_from_input(response);
        if (keys_json != NULL) {
            const char *action = get_command_from_json(keys_json);
            if ((action != NULL) && (strcmp(CHECK_KEYS_ENTRY, action) == 0)) {
                char *keys = get_keys_from_json(keys_json);
                if (keys != NULL) {
                    /* Append to rkey the alert keys that the AR script will use */
                    strcat(rkey, keys);
                    os_free(keys);
                }
            }
            cJSON_Delete(keys_json);
        }

        added_before = 0;

        /* We don't need to add to the list if the timeout_value == 0 */
        if (timeout_value) {
            /* Check if this command was already executed */
            timeout_node = OSList_GetFirstNode(timeout_list);
            while (timeout_node) {
                timeout_data *list_entry;

                list_entry = (timeout_data *)timeout_node->data;
                if (strcmp(list_entry->rkey, rkey) == 0) {
                    /* Means we executed this command before and we don't need to add it again */
                    added_before = 1;

                    /* Update the timeout */
                    mdebug1("Command already received, updating time of addition to now.");
                    list_entry->time_of_addition = curr_time;
                    list_entry->time_to_block = timeout_value;
                    break;
                }

                /* Continue with the next entry in timeout list */
                timeout_node = OSList_GetNextNode(timeout_list);
            }

            /* If it wasn't added before, do it now */
            if (!added_before) {
                /* Timeout parameters */
                cJSON_ReplaceItemInObject(json_root, "command", cJSON_CreateString(DELETE_ENTRY));

                /* Create the timeout entry */
                os_calloc(1, sizeof(timeout_data), timeout_entry);
                os_calloc(2, sizeof(char *), timeout_entry->command);
                os_strdup(cmd[0], timeout_entry->command[0]);
                timeout_entry->command[1] = NULL;
                timeout_entry->parameters = cJSON_PrintUnformatted(json_root);
                os_strdup(rkey, timeout_entry->rkey);
                timeout_entry->time_of_addition = curr_time;
                timeout_entry->time_to_block = timeout_value;

                /* Add command to the timeout list */
                mdebug1("Adding command '%s %s' to the timeout list, with a timeout of '%ds'.",
                    timeout_entry->command[0],
                    timeout_entry->parameters,
                    timeout_entry->time_to_block
                );

                if (!OSList_AddData(timeout_list, timeout_entry)) {
                    merror(LIST_ADD_ERROR);
                    FreeTimeoutEntry(timeout_entry);
                }
            }
        }

        /* If it wasn't added before, continue execution */
        if (!added_before) {
            /* Continue command */
            cJSON_ReplaceItemInObject(json_root, "command", cJSON_CreateString(CONTINUE_ENTRY));
        } else {
            /* Abort command */
            cJSON_ReplaceItemInObject(json_root, "command", cJSON_CreateString(ABORT_ENTRY));
        }

        os_free(cmd_parameters);
        cmd_parameters = cJSON_PrintUnformatted(json_root);

        /* Send continue/abort message to AR script */
        fprintf(wfd->file_in, "%s\n", cmd_parameters);
        fflush(wfd->file_in);

        wpclose(wfd);
    } else {
        merror(EXEC_CMD_FAIL, strerror(errno), errno);
    }

    os_free(cmd_parameters);
    cJSON_Delete(json_root);
}

#endif /* WIN32 */
