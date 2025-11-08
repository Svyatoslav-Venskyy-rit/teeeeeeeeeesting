#!/bin/bash

# CCDC Hardening Script v2.1 - Non-Destructive User Disablement
# Implements the Triad of Defense: Expiration, Nologin Shell, Password Lock

# --- Configuration Section ---

# Define the explicit whitelist of users NOT to disable
WHITELIST=(
    'datadog' 'dd-dog' 'whiteteam' 'blackteam' 'grayteam'
    'fathertime' 'chronos' 'aion' 'kairos' 'merlin'
    'terminator' 'mrpeabody' 'jamescole' 'docbrown'
    'professorparadox' 'drwho' 'martymcfly' 'arthurdent'
    'sambeckett' 'loki' 'riphunter' 'theflash' 'tonystark'
    'drstrange' 'bartallen'
)

# Minimum UID threshold for non-system users (standard is 1000)
MIN_UID=1000

# Set the Nologin shell path (verify path based on distribution)
NOLOGIN_SHELL="/usr/sbin/nologin"
# Alternative for older systems: NOLOGIN_SHELL="/bin/nologin"

# --- Main Logic ---

echo "Starting CCDC User Hardening Script (v2.1)..."
echo "Targeting users with UID >= $MIN_UID not found in the explicit whitelist."

# Function to check if a user is in the WHITELIST array
is_whitelisted() {
    local user="$1"
    for wuser in "${WHITELIST[@]}"; do
        if [[ "$user" == "$wuser" ]]; then
            return 0 # User found in whitelist
        fi
    done
    return 1 # User not found
}

# Iterate through all non-system users defined in /etc/passwd
# We filter by minimum UID and ensure the user's default shell is not already set to /sbin/nologin
cut -d: -f1,3,7 /etc/passwd | while IFS=: read -r username uid shell; do
    
    # 1. Filter out system accounts (UID check)
    if (( uid < MIN_UID )); then
        continue
    fi

    # 2. Filter out whitelisted accounts (Explicit check)
    if is_whitelisted "$username"; then
        echo "[INFO] Skipping Whitelisted User: $username (UID: $uid)"
        continue
    fi
    
    # 3. Disablement Action: Triad of Defense
    echo " Disabling unauthorized user: $username (UID: $uid)"

    # a) Primary Defense: Set account expiration to 1970-01-02
    # This blocks login via PAM/shadow mechanisms for all vectors (passwords, keys).
    # '1' is the safest, unambiguous expired value.
    if! usermod -e 1 "$username"; then
        echo " Failed to set expiration date for $username."
    else
        echo "  Account Expired."
    fi

    # b) Secondary Defense: Change shell to nologin
    # This prevents interactive sessions even if authentication partially succeeds.
    if! usermod -s "$NOLOGIN_SHELL" "$username"; then
        echo " Failed to set nologin shell for $username."
    else
        echo "  Shell set to $NOLOGIN_SHELL."
    fi

    # c) Tertiary Defense: Lock the password hash
    # Redundant layer to block password-based attacks.
    if! passwd -l "$username"; then
        echo " Failed to lock password for $username."
    else
        echo "  Password hash locked."
    fi

done

echo "User hardening sweep complete."
