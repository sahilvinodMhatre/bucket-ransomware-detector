buckets=()
objects=()
encrypted_files_count=0
state_file="encrypted_state.json"
bucket_state_file="bucket_security_state.json"

# If a state bucket is provided as first argument, use it
if [ -n "$1" ]; then
    # Make sure we have the gs:// prefix
    if [[ "$1" == gs://* ]]; then
        state_bucket="$1"
    else
        state_bucket="gs://$1"
    fi
    echo "Using provided state bucket: $state_bucket"
else
    # Get project ID for default bucket name
    project_id=$(gcloud config get-value project 2>/dev/null)
    
    # Ensure project ID is valid
    if [ -z "$project_id" ]; then
        echo "Error: Could not determine project ID. Please provide state bucket as parameter."
        exit 1
    fi
    
    state_bucket="gs://$project_id"
    echo "Using default state bucket: $state_bucket"
fi

# Flag to track if state files are newly created
is_new_state_file=false
is_new_bucket_state_file=false

# FORCE LOGGING EVEN ON FIRST RUN (set to false to restore normal behavior)
FORCE_LOGGING=true

# Check if the bucket exists, if not create it
if ! gsutil ls $state_bucket > /dev/null 2>&1; then
    echo "Creating bucket $state_bucket..."
    gsutil mb $state_bucket
fi

# Try to download existing state files from bucket
if gsutil stat $state_bucket/$state_file > /dev/null 2>&1; then
    echo "Downloading existing state file from $state_bucket/$state_file..."
    gsutil cp $state_bucket/$state_file ./$state_file
else
    echo "No existing state file found in bucket. Creating new state file..."
    echo '{"logged_files": []}' > "$state_file"
    is_new_state_file=true
fi

if gsutil stat $state_bucket/$bucket_state_file > /dev/null 2>&1; then
    echo "Downloading existing bucket security state file..."
    gsutil cp $state_bucket/$bucket_state_file ./$bucket_state_file
    
    # Check if the downloaded file has the old format with lifecycle_rules
    if jq -e '.no_lifecycle_rules_reported' "$bucket_state_file" > /dev/null 2>&1; then
        echo "Cleaning up old fields in state file..."
        jq 'del(.no_lifecycle_rules_reported)' "$bucket_state_file" > "${bucket_state_file}.tmp" && 
        mv "${bucket_state_file}.tmp" "$bucket_state_file"
    fi
else
    echo "No existing bucket security state file found. Creating new file..."
    echo '{"no_versioning_reported": [], "no_retention_lock_reported": [], "no_retention_policy_reported": [], "no_soft_delete_policy_reported": []}' > "$bucket_state_file"
    is_new_bucket_state_file=true
fi

function get_all_buckets() {
    local bucket_list
    bucket_list=$(gcloud storage buckets list --format=json)
    
    # Clean approach to extract bucket names
    while IFS= read -r bucket_name; do
        # Remove gs:// prefix and any whitespace/special chars
        bucket_name=$(echo "${bucket_name#gs://}" | tr -d '\r\n' | xargs)
        # Only add non-empty bucket names
        if [[ -n "$bucket_name" ]]; then
            buckets+=("$bucket_name")
            echo "Added bucket: '$bucket_name'"
        fi
    done < <(echo "$bucket_list" | jq -r '.[] | .name')
}

function get_all_objects() {
    local bucket_name=$1
    
    # Make sure there are no trailing slashes, spaces, or special chars
    bucket_name=$(echo "$bucket_name" | tr -d '\r\n' | xargs)
    
    echo "Executing: gsutil ls gs://$bucket_name/*"
    object_list=$(gsutil ls "gs://$bucket_name/*" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo "Error accessing bucket: $bucket_name"
        return 1
    fi
    
    # Process each line and filter out directories
    while IFS= read -r object; do
        # Skip empty lines, directory listings ending with :, and paths ending with /
        if [[ -n "$object" && ! "$object" =~ :$ && ! "$object" =~ /$ ]]; then
            objects+=("$object")
        fi
    done < <(echo "$object_list" | grep -v '^$')
}

function encryption_detection() {
    local object_name=$1
    
    if [[ -z "$object_name" ]]; then
        echo "Error: No object name provided"
        return 2
    fi
    
    local json_output
    json_output=$(gcloud storage objects describe "$object_name" --format=json)
    
    if echo "$json_output" | grep -q "encryption_algorithm"; then
        return 0
    fi
    return 1
}

# Check if a file has already been logged
function is_file_logged() {
    local object_path=$1
    jq --arg path "$object_path" '.logged_files | index($path) != null' "$state_file" | grep -q "true"
    return $?
}

# Add a file to the logged files list
function add_to_logged_files() {
    local object_path=$1
    jq --arg path "$object_path" '.logged_files += [$path]' "$state_file" > "${state_file}.tmp" && 
    mv "${state_file}.tmp" "$state_file"
}

# Check if bucket has been reported for no versioning
function is_no_versioning_reported() {
    local bucket_name=$1
    jq --arg bucket "$bucket_name" '.no_versioning_reported | index($bucket) != null' "$bucket_state_file" | grep -q "true"
    return $?
}

# Check if bucket has been reported for no retention lock
function is_no_retention_lock_reported() {
    local bucket_name=$1
    jq --arg bucket "$bucket_name" '.no_retention_lock_reported | index($bucket) != null' "$bucket_state_file" | grep -q "true"
    return $?
}

# Check if bucket has been reported for no retention policy
function is_no_retention_policy_reported() {
    local bucket_name=$1
    jq --arg bucket "$bucket_name" '.no_retention_policy_reported | index($bucket) != null' "$bucket_state_file" | grep -q "true"
    return $?
}

# Check if bucket has been reported for no soft delete policy
function is_no_soft_delete_policy_reported() {
    local bucket_name=$1
    jq --arg bucket "$bucket_name" '.no_soft_delete_policy_reported | index($bucket) != null' "$bucket_state_file" | grep -q "true"
    return $?
}

# Add a bucket to the no versioning reported list
function add_to_no_versioning_reported() {
    local bucket_name=$1
    jq --arg bucket "$bucket_name" '.no_versioning_reported += [$bucket]' "$bucket_state_file" > "${bucket_state_file}.tmp" && 
    mv "${bucket_state_file}.tmp" "$bucket_state_file"
}

# Add a bucket to the no retention lock reported list
function add_to_no_retention_lock_reported() {
    local bucket_name=$1
    jq --arg bucket "$bucket_name" '.no_retention_lock_reported += [$bucket]' "$bucket_state_file" > "${bucket_state_file}.tmp" && 
    mv "${bucket_state_file}.tmp" "$bucket_state_file"
}

# Add a bucket to the no retention policy reported list
function add_to_no_retention_policy_reported() {
    local bucket_name=$1
    jq --arg bucket "$bucket_name" '.no_retention_policy_reported += [$bucket]' "$bucket_state_file" > "${bucket_state_file}.tmp" && 
    mv "${bucket_state_file}.tmp" "$bucket_state_file"
}

# Add a bucket to the no soft delete policy reported list
function add_to_no_soft_delete_policy_reported() {
    local bucket_name=$1
    jq --arg bucket "$bucket_name" '.no_soft_delete_policy_reported += [$bucket]' "$bucket_state_file" > "${bucket_state_file}.tmp" && 
    mv "${bucket_state_file}.tmp" "$bucket_state_file"
}

# Check if bucket has retention policy locked
function check_retention_locked() {
    local bucket_name=$1
    local bucket_info
    
    bucket_info=$(gcloud storage buckets describe "gs://$bucket_name" --format="json" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        echo "Error getting bucket info for $bucket_name"
        return 2
    fi
    
    # Check if retention_policy exists and is locked
    if echo "$bucket_info" | jq -e '.retention_policy.isLocked == true' > /dev/null 2>&1; then
        return 0  # Retention policy is locked
    fi
    return 1  # Retention policy is not locked or doesn't exist
}

# Check if bucket has versioning enabled (part of soft delete)
function check_versioning_enabled() {
    local bucket_name=$1
    local bucket_info
    
    bucket_info=$(gcloud storage buckets describe "gs://$bucket_name" --format="json" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        echo "Error getting bucket info for $bucket_name"
        return 2
    fi
    
    # Check if versioning is enabled
    if echo "$bucket_info" | jq -e '.versioning_enabled == true' > /dev/null 2>&1; then
        return 0  # Versioning is enabled
    fi
    return 1  # Versioning is not enabled
}

# Check if bucket has appropriate lifecycle rules (part of soft delete)
function check_lifecycle_rules() {
    local bucket_name=$1
    local bucket_info
    
    bucket_info=$(gcloud storage buckets describe "gs://$bucket_name" --format="json" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        echo "Error getting bucket info for $bucket_name"
        return 2
    fi
    
    # Check if lifecycle rules exist
    if echo "$bucket_info" | jq -e '.lifecycle.rule != null and (.lifecycle.rule | length > 0)' > /dev/null 2>&1; then
        # Check for rules that manage older versions
        if echo "$bucket_info" | jq -e '.lifecycle.rule[] | select(.condition.isLive == false or .condition.numNewerVersions > 0)' > /dev/null 2>&1; then
            return 0  # Appropriate lifecycle rules exist
        fi
    fi
    return 1  # No appropriate lifecycle rules
}

# Check if bucket has soft delete policy enabled and properly configured
function check_soft_delete_policy() {
    local bucket_name=$1
    local bucket_info
    
    bucket_info=$(gcloud storage buckets describe "gs://$bucket_name" --format="json" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        echo "Error getting bucket info for $bucket_name"
        return 2
    fi
    
    # First check if soft_delete_policy exists
    if echo "$bucket_info" | jq -e '.soft_delete_policy != null' > /dev/null 2>&1; then
        # Check if retention duration is greater than 0 seconds
        if echo "$bucket_info" | jq -e '.soft_delete_policy.retentionDurationSeconds == "0"' > /dev/null 2>&1; then
            return 1  # Soft delete policy is disabled
        fi
    fi
    
    return 0 # No soft delete policy or retention is 0
}

# Check if bucket has retention policy set
function check_retention_policy() {
    local bucket_name=$1
    local bucket_info
    
    bucket_info=$(gcloud storage buckets describe "gs://$bucket_name" --format="json" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        echo "Error getting bucket info for $bucket_name"
        return 2
    fi
    
    # Check if retention_policy exists
    if echo "$bucket_info" | jq -e '.retention_policy.retentionPeriod != null' > /dev/null 2>&1; then
        return 0  # Retention policy exists
    fi
    return 1  # No retention policy
}

# Function to safely send logs to Cloud Logging
send_log() {
    local log_name=$1
    local log_message=$2
    local severity=$3
    
    echo "----------------------------------------------"
    echo "VERBOSE DEBUG: ATTEMPTING TO LOG"
    echo "LOG NAME: $log_name"
    echo "LOG MESSAGE: $log_message"
    echo "SEVERITY: $severity"
    
    # Add a unique identifier to each log to help with debugging
    local log_id=$(date +%s%N | cut -b1-13)
    log_message="$log_message | log_id: $log_id"
    
    # Print the exact command we're going to run
    echo "EXECUTING COMMAND: gcloud logging write \"$log_name\" \"$log_message\" --severity=\"$severity\""
    
    # Use a temporary file to capture any errors and output
    local temp_err=$(mktemp)
    local temp_out=$(mktemp)
    
    # Execute the command with output and error capture
    if gcloud logging write "$log_name" "$log_message" --severity="$severity" > "$temp_out" 2>"$temp_err"; then
        echo "✅ COMMAND SUCCEEDED!"
        echo "COMMAND OUTPUT:"
        cat "$temp_out"
        echo "LOG WRITTEN WITH ID: $log_id"
    else
        echo "❌ COMMAND FAILED! Exit code: $?"
        echo "ERROR OUTPUT:"
        cat "$temp_err"
        echo "STANDARD OUTPUT:"
        cat "$temp_out"
        echo "PLEASE CHECK YOUR PERMISSIONS TO WRITE LOGS"
    fi
    
    # Try an alternate method as a test
    echo "TRYING ALTERNATE METHOD: Writing to syslog instead"
    logger -t "DETECTOR_SCRIPT" "$log_name: $log_message"
    echo "SYSLOG ATTEMPT COMPLETE"
    
    rm -f "$temp_err" "$temp_out"
    echo "----------------------------------------------"
}

# Main execution 


echo "Getting bucket list..."
get_all_buckets

echo "Found ${#buckets[@]} buckets:"
for bucket in "${buckets[@]}"; do
    echo "Bucket: [$bucket]"  # Square brackets to show exact string
done

# Initialize security counters
no_versioning_count=0
no_retention_lock_count=0
no_retention_policy_count=0
no_lifecycle_rules_count=0
no_soft_delete_count=0
new_no_versioning_count=0
new_no_retention_lock_count=0
new_no_retention_policy_count=0
new_no_soft_delete_count=0

# Print logging status based on state file
if [ "$is_new_bucket_state_file" = true ]; then
    if [ "$FORCE_LOGGING" = true ]; then
        echo "First run with FORCE_LOGGING=true - WILL SEND ALERTS FOR ALL ISSUES"
    else
        echo "First run - establishing baseline (no alerts will be sent)"
    fi
else
    echo "State file exists - will report new issues to logging"
fi

# echo "==============================================="
# echo "TESTING CLOUD LOGGING ACCESS"
# echo "This will verify if we can write to Cloud Logging"
# send_log "detector_script_test" "Script is running a test log entry" "INFO"
# echo "TEST LOG ATTEMPT COMPLETED"
# echo "==============================================="

echo "Checking bucket security features..."
for bucket in "${buckets[@]}"; do
    # Check versioning (part of soft delete)
    has_versioning=false
    check_versioning_enabled "$bucket"
    if [ $? -eq 0 ]; then
        has_versioning=true
    else
        no_versioning_count=$((no_versioning_count + 1))
        
        # Log buckets without versioning if not already reported and not initial setup
        if ! is_no_versioning_reported "$bucket"; then
            if [ "$is_new_bucket_state_file" = false ] || [ "$FORCE_LOGGING" = true ]; then
                echo "Logging bucket without versioning: $bucket"
                send_log "bucket_no_versioning1" "bucket: gs://$bucket | timestamp: $(date '+%Y-%m-%d %H:%M:%S')" "WARNING"
                new_no_versioning_count=$((new_no_versioning_count + 1))
            else
                echo "SKIPPING LOG: First run, not logging bucket without versioning: $bucket"
            fi
            # Always add to reported list
            add_to_no_versioning_reported "$bucket"
        fi
    fi
    
    # Check if soft delete protection is missing
    check_soft_delete_policy "$bucket"
    if [ $? -eq 1 ]; then
        no_soft_delete_count=$((no_soft_delete_count + 1))
        
        # Log buckets without soft delete policy if not already reported and not initial setup
        if ! is_no_soft_delete_policy_reported "$bucket"; then
            if [ "$is_new_bucket_state_file" = false ] || [ "$FORCE_LOGGING" = true ]; then
                echo "Logging bucket without soft delete policy: $bucket"
                send_log "bucket_no_soft_delete1" "bucket: gs://$bucket | Soft delete policy disabled/missing | timestamp: $(date '+%Y-%m-%d %H:%M:%S')" "WARNING"
                new_no_soft_delete_count=$((new_no_soft_delete_count + 1))
            else
                echo "SKIPPING LOG: First run, not logging bucket without soft delete policy: $bucket"
            fi
            # Always add to reported list
            add_to_no_soft_delete_policy_reported "$bucket"
        fi
    fi
    
    # Check retention policy
    check_retention_policy "$bucket"
    if [ $? -ne 0 ]; then
        no_retention_policy_count=$((no_retention_policy_count + 1))
        
        # Log buckets without retention policy if not already reported and not initial setup
        if ! is_no_retention_policy_reported "$bucket"; then
            if [ "$is_new_bucket_state_file" = false ] || [ "$FORCE_LOGGING" = true ]; then
                echo "Logging bucket without retention policy: $bucket"
                send_log "bucket_no_retention_policy1" "bucket: gs://$bucket | timestamp: $(date '+%Y-%m-%d %H:%M:%S')" "WARNING"
                new_no_retention_policy_count=$((new_no_retention_policy_count + 1))
            else
                echo "SKIPPING LOG: First run, not logging bucket without retention policy: $bucket"
            fi
            # Always add to reported list
            add_to_no_retention_policy_reported "$bucket"
        fi
    fi
    
    # Check retention lock
    check_retention_locked "$bucket"
    if [ $? -ne 0 ]; then
        no_retention_lock_count=$((no_retention_lock_count + 1))
        
        # Log buckets without retention lock if not already reported and not initial setup
        if ! is_no_retention_lock_reported "$bucket"; then
            if [ "$is_new_bucket_state_file" = false ] || [ "$FORCE_LOGGING" = true ]; then
                echo "Logging bucket without retention lock: $bucket"
                send_log "bucket_no_retention_lock1" "bucket: gs://$bucket | timestamp: $(date '+%Y-%m-%d %H:%M:%S')" "WARNING"
                new_no_retention_lock_count=$((new_no_retention_lock_count + 1))
            else
                echo "SKIPPING LOG: First run, not logging bucket without retention lock: $bucket"
            fi
            # Always add to reported list
            add_to_no_retention_lock_reported "$bucket"
        fi
    fi
done

echo "Processing buckets for encrypted objects..."
for bucket in "${buckets[@]}"; do
    get_all_objects "$bucket"
done

echo "Objects (excluding directories, ${#objects[@]} total):"
echo "" > encrypted_files.txt

# Count of newly detected encrypted files in this run
new_encrypted_files=0

for object in "${objects[@]}"; do
    encryption_detection "$object"
    if [ $? -eq 0 ]; then
        encrypted_files_count=$((encrypted_files_count + 1))
        echo " $object | $(date '+%Y-%m-%d %H:%M:%S')" >> encrypted_files.txt
        
        # Check if this file has already been logged and not initial setup
        if ! is_file_logged "$object"; then
            if [ "$is_new_state_file" = false ] || [ "$FORCE_LOGGING" = true ]; then
                # Log only new encrypted files
                echo "Logging encrypted file: $object"
                send_log "encrypted_bucket_files1" "object: $object | timestamp: $(date '+%Y-%m-%d %H:%M:%S')" "INFO"
                new_encrypted_files=$((new_encrypted_files + 1))
            else
                echo "SKIPPING LOG: First run, not logging encrypted file: $object"
            fi
            # Always add to logged files
            add_to_logged_files "$object"
        fi
    fi
done

# Upload results to bucket
gsutil cp encrypted_files.txt $state_bucket/encrypted_files.txt
gsutil cp $state_file $state_bucket/$state_file
gsutil cp $bucket_state_file $state_bucket/$bucket_state_file

echo "⚠️  Total encrypted files count: $encrypted_files_count"
echo "⚠️  Newly detected encrypted files: $new_encrypted_files"
echo "⚠️  Buckets missing versioning: $no_versioning_count"
echo "⚠️  Buckets missing soft delete protection: $no_soft_delete_count"
echo "⚠️  Buckets missing retention policy: $no_retention_policy_count"
echo "⚠️  Buckets missing retention lock: $no_retention_lock_count"
echo "⚠️  Newly reported buckets missing versioning: $new_no_versioning_count"
echo "⚠️  Newly reported buckets missing soft delete: $new_no_soft_delete_count"
echo "⚠️  Newly reported buckets missing retention policy: $new_no_retention_policy_count"
echo "⚠️  Newly reported buckets missing retention lock: $new_no_retention_lock_count"
echo "State saved to $state_file and uploaded to $state_bucket/$state_file" 
echo "Bucket security state saved to $bucket_state_file and uploaded to $state_bucket/$bucket_state_file" 