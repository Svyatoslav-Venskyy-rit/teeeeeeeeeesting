#!/bin/bash

# Configuration
LOGFILE="/var/log/ccdc_user_remediation_$(date +%F_%H%M%S).log"
# --- FULL WHITELIST ---
# Users NOT to disable. This includes system-managed accounts, team accounts, and
# required scored user accounts.
WHITELIST_USERS="root datadog dd-dog whiteteam blackteam grayteam fathertime chronos aion kairos merlin terminator mrpeabody jamescole docbrown professorparadox drwho martymcfly arthurdent sambeckett loki riphunter theflash tonystark drstrange bartallen"
# Standard UID threshold for regular users
SYSTEM_UIDS_MAX=1000

echo "$(date): Starting Unexpected User Scan for Disablement" | tee -a $LOGFILE
echo "--- LOG FILE: $LOGFILE ---" | tee -a $LOGFILE
echo "USERS EXCLUDED FROM DISABLEMENT (WHITELIST): $WHITELIST_USERS" >> $LOGFILE
echo "---" >> $LOGFILE

# Get all accounts with UID >= 1000 (standard for regular users)
ALL_USERS=$(getent passwd | awk -F: -v max_uid=$SYSTEM_UIDS_MAX '{if ($3 >= max_uid) print $1}')
USERS_TO_DISABLE=()

# Filter out the explicitly whitelisted users from the list of high-UID accounts
for user in $ALL_USERS; do
    IS_WHITELISTED=0
    # Check if the user is in the WHITELIST_USERS string
    if [[ " $WHITELIST_USERS " =~ " $user " ]]; then
        IS_WHITELISTED=1
    fi
    
    # Only add the user to the disable list if they are NOT whitelisted
    if [ $IS_WHITELISTED -eq 0 ]; then
        USERS_TO_DISABLE+=("$user")
    fi
done

echo "Found ${#USERS_TO_DISABLE[@]} unexpected user(s) for disablement." | tee -a $LOGFILE

# --- Disablement Loop ---
if [ ${#USERS_TO_DISABLE[@]} -eq 0 ]; then
    echo "No unexpected accounts found (UID >= $SYSTEM_UIDS_MAX) to disable." | tee -a $LOGFILE
else
    echo "--- DISABLING UNEXPECTED ACCOUNTS ---" | tee -a $LOGFILE
    for user_to_disable in "${USERS_TO_DISABLE[@]}"; do
        
        # Get user details for logging
        USER_INFO=$(getent passwd "$user_to_disable" | cut -d: -f1,3-7) # Show user, uid, gid, comment, home, shell
        
        echo "🔐 Attempting to disable user: $user_to_disable (Details: $USER_INFO)" | tee -a $LOGFILE
        
        # Disable the user by locking their password (usermod -L)
        # This prevents the user from logging in.
        usermod -L "$user_to_disable"
        
        if [ $? -eq 0 ]; then
            echo "$(date): ✅ SUCCESS: Disabled (Locked) user $user_to_disable." | tee -a $LOGFILE
        else
            echo "$(date): ❌ ERROR: Failed to disable user $user_to_disable." | tee -a $LOGFILE
        fi
        
    done
fi

echo -e "\n$(date): User disablement complete." | tee -a $LOGFILE

# --- Instructions ---
# To run this script:
# 1. Save it (e.g., as disable_users.sh)
# 2. Make it executable: chmod +x disable_users.sh
# 3. Run with root privileges: sudo ./disable_users.sh
