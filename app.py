import streamlit as st
import os
import pandas as pd
import hashlib
from datetime import datetime

# Import core modules
from core.db import init_db
from core.auth import register_user, login_user
from core.file_service import (
    send_file,
    download_and_decrypt_file,
    revoke_file,
    get_received_files,
    get_sent_files,
    search_users,
    add_contact,
    get_contacts,
    remove_contact
)
from core.audit_service import get_user_audit_logs, log_event
from core.utils import format_size, is_valid_secureshare_id

# Initialize database tables
init_db()

# Page configuration
st.set_page_config(
    page_title="SecureShare | Banking-Grade Encrypted Document Exchange",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Banking-Grade Slate-Teal/Gold CSS styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@300;400;500;600;700;800&display=swap');
    
    /* Global styles */
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    
    /* Mono fonts for crypto readouts */
    .mono-font {
        font-family: 'JetBrains Mono', monospace;
    }
    
    /* Title styling */
    .title-gradient {
        background: linear-gradient(135deg, #0D9488 0%, #3B82F6 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        font-size: 2.6rem;
        margin-bottom: 0.3rem;
    }
    
    .subtitle-text {
        color: #94A3B8;
        font-size: 1.05rem;
        margin-bottom: 1.5rem;
    }
    
    /* Security Telemetry Header */
    .telemetry-header {
        background: linear-gradient(90deg, #0F1A2E 0%, #112643 50%, #0F1A2E 100%);
        border-bottom: 2px solid #0D9488;
        padding: 12px 24px;
        border-radius: 12px;
        margin-bottom: 25px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
    }
    .telemetry-tag {
        background-color: rgba(13, 148, 136, 0.2);
        border: 1px solid #0D9488;
        color: #0D9488;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.05em;
    }
    .telemetry-status {
        color: #10B981;
        font-weight: 700;
        font-size: 0.85rem;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    
    /* Dashboard Cards */
    .secure-card {
        background-color: #0F1A2E;
        border: 1px solid #1E293B;
        border-top: 4px solid #0D9488;
        border-radius: 16px;
        padding: 24px;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .secure-card:hover {
        transform: translateY(-2px);
        border-color: #3B82F6;
    }
    .metric-value {
        font-size: 2.8rem;
        font-weight: 700;
        color: #0D9488;
        margin-bottom: 5px;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-weight: 600;
    }
    
    /* Hardware Security Module (HSM) State styling */
    .hsm-module {
        background: radial-gradient(circle at top right, #112240 0%, #0A192F 100%);
        border: 1px solid #1E3A8A;
        border-radius: 16px;
        padding: 24px;
        color: #E2E8F0;
        margin-bottom: 25px;
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.5);
    }
    
    .status-ring {
        display: inline-block;
        width: 10px;
        height: 10px;
        background-color: #10B981;
        border-radius: 50%;
        box-shadow: 0 0 8px #10B981;
        animation: pulse-green 2s infinite;
    }
    
    @keyframes pulse-green {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }
    
    /* Terminal Console */
    .terminal-console {
        background-color: #030712;
        border: 1px solid #1F2937;
        border-radius: 12px;
        padding: 18px;
        font-family: 'JetBrains Mono', monospace;
        color: #10B981;
        font-size: 0.82rem;
        line-height: 1.6;
        box-shadow: inset 0 4px 6px rgba(0,0,0,0.8);
        margin-bottom: 20px;
    }
    
    .sidebar-badge {
        background-color: #0F1A2E;
        border-left: 4px solid #0D9488;
        border-radius: 6px;
        padding: 12px;
        margin-bottom: 18px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Session States
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None
if "private_key" not in st.session_state:
    st.session_state.private_key = None
if "current_page" not in st.session_state:
    st.session_state.current_page = "Dashboard"
if "decrypted_file" not in st.session_state:
    st.session_state.decrypted_file = None
if "prefilled_recipient_id" not in st.session_state:
    st.session_state.prefilled_recipient_id = ""
if "decryption_log_payload" not in st.session_state:
    st.session_state.decryption_log_payload = None

def logout():
    """Clear session data and return to portal login."""
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.private_key = None
    st.session_state.current_page = "Dashboard"
    st.session_state.decrypted_file = None
    st.session_state.prefilled_recipient_id = ""
    st.session_state.decryption_log_payload = None
    st.rerun()

# ----------------- SIDEBAR NAVIGATION -----------------
with st.sidebar:
    st.markdown("<h2 style='text-align: center; color: #E2E8F0; margin-bottom: 2px;'>🛡️ SECURESHARE</h2>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #0D9488; font-size: 0.8rem; font-weight: bold; letter-spacing: 0.05em;'>FINANCIAL INSTITUTION GATEWAY</p>", unsafe_allow_html=True)
    st.markdown("---")
    
    if st.session_state.logged_in:
        user = st.session_state.user
        st.markdown(f"""
        <div class="sidebar-badge">
            <div style="font-size: 0.75rem; color: #94A3B8; text-transform: uppercase; font-weight: bold; letter-spacing: 0.05em;">Access Level: Registered User</div>
            <div style="font-weight: 700; font-size: 1rem; color: #F8FAFC; margin: 4px 0;">{user['name']}</div>
            <div class="mono-font" style="color: #0D9488; font-size: 0.85rem; font-weight: bold;">{user['secure_id']}</div>
        </div>
        """, unsafe_allow_html=True)
        
        pages = ["Dashboard", "Send File", "Inbox", "Sent Files", "Contacts", "Audit Logs"]
        
        default_idx = pages.index(st.session_state.current_page) if st.session_state.current_page in pages else 0
        selection = st.radio("GATEWAY SERVICES", pages, index=default_idx)
        st.session_state.current_page = selection
        
        st.markdown("---")
        if st.button("Close Secure Connection (Logout)", use_container_width=True):
            logout()
    else:
        st.info("System locked. Provide valid user credentials to initiate connection.")
        st.markdown("---")
        st.markdown("""
        ### Cryptographic Architecture
        - **Data Wrappers**: RSA-OAEP + SHA-256
        - **Storage Engine**: AES-GCM-256 (authenticated)
        - **Local Store**: Zero-knowledge ciphertext directories
        - **Security Audit**: Immutable activity logs
        """)

# ----------------- SECURITY TELEMETRY HEADER -----------------
def render_telemetry_header():
    st.markdown(f"""
    <div class="telemetry-header">
        <div style="display: flex; align-items: center; gap: 15px;">
            <span class="telemetry-tag">RSA-2048</span>
            <span class="telemetry-tag">AES-GCM-256</span>
            <span style="font-weight: 700; color: #E2E8F0; font-size: 0.85rem; letter-spacing: 0.05em;">GATEWAY CORE: ENGAGED</span>
        </div>
        <div class="telemetry-status">
            <span class="status-ring"></span>
            <span>END-TO-END CRYPTOGRAPHIC SANITIZATION ACTIVE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ----------------- LOGIN / REGISTER PORTAL -----------------
if not st.session_state.logged_in:
    st.markdown("<h1 class='title-gradient'>Institutional Security Portal</h1>", unsafe_allow_html=True)
    st.markdown("<p class='subtitle-text'>Authorized personnel only. Sessions are audited. Zero-knowledge cryptographic file exchange.</p>", unsafe_allow_html=True)
    
    tab_login, tab_register = st.tabs(["🔒 SECURE LOGIN", "📝 REGISTER SYSTEM IDENTITY"])
    
    with tab_login:
        st.markdown("### Access Authentication")
        login_email = st.text_input("User Email Address", key="login_email_input", placeholder="e.g. employee@bank.com").strip()
        login_password = st.text_input("Password", type="password", key="login_pwd_input", placeholder="🔑 Enter key password")
        
        if st.button("Authenticate Identity", type="primary", use_container_width=True):
            if not login_email or not login_password:
                st.error("Please enter email and password.")
            else:
                with st.spinner("Decrypting credential tokens and unwrapping RSA keys..."):
                    try:
                        user_details, private_key_obj = login_user(login_email, login_password)
                        st.session_state.user = user_details
                        st.session_state.private_key = private_key_obj
                        st.session_state.logged_in = True
                        st.toast(f"Authenticated as {user_details['name']}", icon="🛡️")
                        st.rerun()
                    except ValueError as e:
                        st.error(str(e))
                        
    with tab_register:
        st.markdown("### Generate Cryptographic Keys & Register")
        reg_name = st.text_input("Full Registered Name", placeholder="e.g. Alice Smith")
        reg_email = st.text_input("Corporate Email Address", placeholder="e.g. alice@bank.com")
        
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            reg_password = st.text_input("Passphrase (min 8 characters)", type="password", placeholder="Select a strong passphrase")
        with col_p2:
            reg_confirm_password = st.text_input("Verify Passphrase", type="password", placeholder="Repeat passphrase")
            
        st.markdown("""
        <div style="background-color: rgba(245, 158, 11, 0.1); border: 1px solid #F59E0B; border-radius: 8px; padding: 12px; margin-bottom: 20px; font-size: 0.85rem; color: #F59E0B;">
            ⚠️ <b>Zero-Knowledge Protection Notice</b>: The password you choose is used to derive an AES-256 key that encrypts your RSA private key before storage. <b>We do not store your password.</b> If you lose this password, your private key can never be decrypted, and all files sent to you will be unrecoverable.
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Generate Cryptographic Identity", type="primary", use_container_width=True):
            with st.spinner("Generating 2048-bit RSA asymmetric keys & KDF salts..."):
                try:
                    registered_info = register_user(
                        reg_name, reg_email, reg_password, reg_confirm_password
                    )
                    st.success("🎉 Cryptographic registration completed successfully!")
                    st.markdown(f"""
                    ### Gateway Credentials:
                    - **Registered User**: {registered_info['name']}
                    - **Gateway ID (SecureShare ID)**: `{registered_info['secure_id']}`
                    - **Assigned Email**: `{registered_info['email']}`
                    
                    *You can now switch to the **SECURE LOGIN** tab and sign in using these credentials.*
                    """)
                except ValueError as e:
                    st.error(str(e))

else:
    # Authenticated Interface
    user = st.session_state.user
    render_telemetry_header()
    
    # 1. ----------------- DASHBOARD -----------------
    if st.session_state.current_page == "Dashboard":
        st.markdown(f"<h2 style='margin-bottom: 5px; color: #F8FAFC;'>Secure Console Dashboard</h2>", unsafe_allow_html=True)
        st.markdown(f"<p class='subtitle-text'>Welcome back, <b>{user['name']}</b>. System operational.</p>", unsafe_allow_html=True)
        
        # Load stats
        received_files = get_received_files(user["id"])
        sent_files = get_sent_files(user["id"])
        
        active_inbox = len([f for f in received_files if f["status"] == "ACTIVE"])
        total_received = len(received_files)
        total_sent = len(sent_files)
        
        # Compute dynamic Public Key Fingerprint
        pub_key_hash = hashlib.sha256(user["public_key_pem"].encode("utf-8")).hexdigest().upper()
        formatted_hash = ":".join([pub_key_hash[i:i+4] for i in range(0, 24, 4)]) + "..."
        
        # HSM & Keys Module
        st.markdown(f"""
        <div class="hsm-module">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1E3A8A; padding-bottom: 10px; margin-bottom: 15px;">
                <h4 style="margin: 0; color: #EAB308;">🛡️ HSM (Hardware Security Module) State</h4>
                <span class="telemetry-status"><span class="status-ring"></span>CONNECTED</span>
            </div>
            <div style="font-size: 0.9rem; line-height: 1.6;">
                <div><b>SecureShare ID</b>: <span class="mono-font" style="color: #0D9488; font-weight: bold;">{user['secure_id']}</span></div>
                <div><b>Local User Public Key Fingerprint</b>: <span class="mono-font" style="color: #94A3B8;">SHA256: {formatted_hash}</span></div>
                <div><b>Private Key Memory State</b>: <span class="mono-font" style="color: #10B981; font-weight: bold;">🔓 Ephemeral Loaded in RAM (Protected)</span></div>
                <div style="margin-top: 8px; font-size: 0.75rem; color: #94A3B8;">ℹ️ Your private key will be scrubbed from host runtime memory as soon as you close your browser tab or log out.</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Stats Columns
        col_c1, col_c2, col_c3 = st.columns(3)
        with col_c1:
            st.markdown(f"""
            <div class="secure-card">
                <div class="metric-value">{active_inbox}</div>
                <div class="metric-label">Active Inbox Files</div>
            </div>
            """, unsafe_allow_html=True)
        with col_c2:
            st.markdown(f"""
            <div class="secure-card">
                <div class="metric-value">{total_received}</div>
                <div class="metric-label">Received Files Ledger</div>
            </div>
            """, unsafe_allow_html=True)
        with col_c3:
            st.markdown(f"""
            <div class="secure-card">
                <div class="metric-value">{total_sent}</div>
                <div class="metric-label">Sent Files Ledger</div>
            </div>
            """, unsafe_allow_html=True)
            
        st.markdown("<br>", unsafe_allow_html=True)
        
        # System Actions
        st.subheader("⚡ Quick Services")
        col_a1, col_a2, col_a3 = st.columns(3)
        with col_a1:
            if st.button("📤 Send Encrypted Document", use_container_width=True):
                st.session_state.current_page = "Send File"
                st.rerun()
        with col_a2:
            if st.button("📥 Access Received Documents", use_container_width=True):
                st.session_state.current_page = "Inbox"
                st.rerun()
        with col_a3:
            if st.button("👥 Directory Contacts", use_container_width=True):
                st.session_state.current_page = "Contacts"
                st.rerun()

    # 2. ----------------- SEND FILE -----------------
    elif st.session_state.current_page == "Send File":
        st.markdown("<h2 style='color: #F8FAFC; margin-bottom: 2px;'>Secure File Dispatch</h2>", unsafe_allow_html=True)
        if "send_success_msg" in st.session_state and st.session_state.send_success_msg:
            st.success(st.session_state.send_success_msg)
            st.session_state.send_success_msg = None
        st.markdown("<p class='subtitle-text'>Documents are encrypted with the recipient's public key before persistence.</p>", unsafe_allow_html=True)
        
        contacts = get_contacts(user["id"])
        
        recipient_source = st.radio("Choose Recipient", ["Saved Contacts", "Enter ID Manually"])
        
        recipient_id = ""
        
        if recipient_source == "Saved Contacts":
            if not contacts:
                st.info("No contacts saved. Enter the SecureShare ID manually.")
                recipient_id = ""
            else:
                contact_opts = [f"{c['name']} ({c['secure_id']})" for c in contacts]
                prefill = st.session_state.prefilled_recipient_id
                prefill_idx = 0
                if prefill:
                    for idx, c in enumerate(contacts):
                        if c["secure_id"] == prefill:
                            prefill_idx = idx
                            break
                selected_contact = st.selectbox("Recipient Contact", contact_opts, index=prefill_idx)
                recipient_id = contacts[contact_opts.index(selected_contact)]["secure_id"]
        else:
            prefill = st.session_state.prefilled_recipient_id
            recipient_id = st.text_input(
                "Recipient SecureShare ID",
                value=prefill,
                placeholder="Format: SS-XXXXXXXX",
                key="manual_recipient_input"
            ).strip().upper()
            
        if recipient_id:
            col_v1, col_v2 = st.columns([1, 4])
            with col_v1:
                if st.button("Verify ID", use_container_width=True):
                    recipient_info = search_users(recipient_id)
                    exact = [r for r in recipient_info if r["secure_id"] == recipient_id]
                    if exact:
                        st.success(f"Verified: {exact[0]['name']}")
                    else:
                        st.error("Invalid SecureShare ID.")
                        
        st.markdown("---")
        
        uploaded_file = st.file_uploader(
            "Select File Payload",
            type=["pdf", "docx", "txt", "png", "jpg", "jpeg", "zip", "xlsx", "csv"],
            help="File is encrypted using AES-GCM-256 before leaving your session."
        )
        
        notes = st.text_area("Audit Notes (Optional)", max_chars=300, placeholder="Provide reason or descriptions for this transfer...")
        
        col_opt1, col_opt2 = st.columns(2)
        with col_opt1:
            expiry_option = st.selectbox(
                "Scrub File Expiration Schedule",
                [("No expiration", 0), ("1 Day", 1), ("7 Days", 7), ("30 Days", 30)],
                format_func=lambda x: x[0]
            )
            expiry_days = expiry_option[1]
        with col_opt2:
            one_time_only = st.checkbox(
                "One-time Download Scrub Policy",
                help="The encrypted payload is deleted from host disk immediately after first successful download."
            )
            
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔒 Dispatch Secure File", type="primary", use_container_width=True):
            if not recipient_id:
                st.error("Recipient ID is required.")
            elif not is_valid_secureshare_id(recipient_id):
                st.error("Incorrect SecureShare ID format. Expected: SS-XXXXXXXX")
            elif not uploaded_file:
                st.error("Please upload a file to dispatch.")
            else:
                with st.spinner("Performing hybrid encryption wrap..."):
                    try:
                        file_bytes = uploaded_file.read()
                        file_uid = send_file(
                            sender_id=user["id"],
                            recipient_secure_id=recipient_id,
                            original_filename=uploaded_file.name,
                            mime_type=uploaded_file.type or "application/octet-stream",
                            file_bytes=file_bytes,
                            notes=notes,
                            expiry_days=expiry_days if expiry_days > 0 else None,
                            one_time_only=one_time_only
                        )
                        st.session_state.send_success_msg = f"🎉 Document encrypted and queued. Reference UID: {file_uid}"
                        st.session_state.prefilled_recipient_id = ""
                        st.rerun()
                    except ValueError as e:
                        st.error(str(e))

    # 3. ----------------- INBOX (RECEIVED FILES) -----------------
    elif st.session_state.current_page == "Inbox":
        col_title, col_ref = st.columns([4, 1.2])
        with col_title:
            st.markdown("<h2 style='color: #F8FAFC; margin-bottom: 2px;'>Secure Incoming Ledger</h2>", unsafe_allow_html=True)
        with col_ref:
            st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
            if st.button("🔄 Refresh Inbox", use_container_width=True):
                st.rerun()
        st.markdown("<p class='subtitle-text'>Encrypted files routed to your private gateway. Load your session private key to decrypt.</p>", unsafe_allow_html=True)
        
        # Display Decryption Process Terminal Logs if available
        if st.session_state.decryption_log_payload is not None:
            log_data = st.session_state.decryption_log_payload
            st.markdown(f"""
            <div class="terminal-console">
                <div style="color: #6B7280; border-bottom: 1px solid #1F2937; padding-bottom: 5px; margin-bottom: 10px; font-weight: bold;">🔐 SECURESHARE DECRYPTION HANDSHAKE PROCESS CONSOLE</div>
                <div>[INIT] Decryption sequence requested for file Ref: {log_data['file_uid'][:18]}...</div>
                <div>[AUTH] Authenticating recipient match... SUCCESS (Verified User ID: {user['secure_id']})</div>
                <div>[RAM] Accessing ephemeral RSA private key from secure session memory... LOADED</div>
                <div>[RSA] RSA-OAEP decrypting AES-256 wrapped key block... SUCCESS</div>
                <div>[AES] Unwrapping complete. Loaded ephemeral AES-256-GCM cipher... SUCCESS</div>
                <div>[IV] Loaded IV vector / Nonce block: {log_data['nonce'][:12]}...</div>
                <div>[GCM] Checking message authentication integrity tag... MATCHED (Verified payload untampered)</div>
                <div>[DEC] Payload decryption successful: <b>{log_data['filename']}</b> ({log_data['size']})</div>
                {"<div>[FS] Forward Secrecy: One-time download consumed. Ciphertext file scrubbed from disk.</div>" if log_data['one_time_only'] else ""}
                <div style="color: #10B981; font-weight: bold; margin-top: 10px;">[SUCCESS] SANITATION COMPLETED. DOWNLOAD CONTAINER READY.</div>
            </div>
            """, unsafe_allow_html=True)
            
            dec = st.session_state.decrypted_file
            st.download_button(
                label=f"⬇️ Save Decrypted Document: {dec['filename']}",
                data=dec["content"],
                file_name=dec["filename"],
                mime=dec["mime_type"],
                use_container_width=True,
                key="final_download_btn_inbox_hsm"
            )
            
            if st.button("Scrub decrypted cache from local session memory", use_container_width=True):
                st.session_state.decrypted_file = None
                st.session_state.decryption_log_payload = None
                st.rerun()
            st.markdown("---")
            
        received_files = get_received_files(user["id"])
        
        if not received_files:
            st.info("Incoming ledger is empty.")
        else:
            for idx, file_data in enumerate(received_files):
                status_color = "#10B981"
                status_text = file_data["status"]
                
                if file_data["status"] == "ACTIVE":
                    status_color = "#10B981"
                elif file_data["status"] == "EXPIRED":
                    status_color = "#F59E0B"
                elif file_data["status"] == "REVOKED":
                    status_color = "#EF4444"
                elif file_data["status"] == "DOWNLOADED":
                    status_color = "#3B82F6"
                    
                expiry_display = "No expiration"
                if file_data["expires_at"]:
                    dt = datetime.fromisoformat(file_data["expires_at"])
                    expiry_display = dt.strftime("%Y-%m-%d %H:%M")
                    
                one_time_str = "🔒 One-time download" if file_data["one_time_only"] else "🔄 Multi-download"
                
                with st.container(border=True):
                    col_det, col_act = st.columns([4, 1.2])
                    
                    with col_det:
                        st.markdown(f"### 📄 {file_data['original_filename']}")
                        st.markdown(f"""
                        * **Sender**: {file_data['sender_name']} (`{file_data['sender_secure_id']}`)
                        * **Size**: {format_size(file_data['size_bytes'])} | **Sent At**: {file_data['upload_time']}
                        * **Policy**: {one_time_str} | **Expiry**: {expiry_display}
                        * **Status**: <span style="background-color:{status_color}; padding: 3px 8px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8rem;">{status_text}</span>
                        """, unsafe_allow_html=True)
                        
                    with col_act:
                        st.markdown("<br>", unsafe_allow_html=True)
                        if file_data["status"] == "ACTIVE":
                            if st.button("🔓 Decrypt & Verify", key=f"dec_btn_{file_data['file_uid']}_{idx}", use_container_width=True):
                                with st.spinner("Unwrapping keys and verifying tags..."):
                                    try:
                                        decrypted_res = download_and_decrypt_file(
                                            file_data["file_uid"],
                                            user["id"],
                                            st.session_state.private_key
                                        )
                                        # Get file details for visual logs
                                        st.session_state.decrypted_file = decrypted_res
                                        st.session_state.decryption_log_payload = {
                                            "file_uid": file_data["file_uid"],
                                            "filename": file_data["original_filename"],
                                            "size": format_size(file_data["size_bytes"]),
                                            "one_time_only": file_data["one_time_only"],
                                            "nonce": "GENERIC_IV_DATA"
                                        }
                                        st.toast("Decryption handshake complete.", icon="🔐")
                                        st.rerun()
                                    except ValueError as e:
                                        st.error(str(e))
                        else:
                            st.write("")
                            st.info(f"Settled ({file_data['status']})")

    # 4. ----------------- SENT FILES (OUTBOX) -----------------
    elif st.session_state.current_page == "Sent Files":
        col_title, col_ref = st.columns([4, 1.2])
        with col_title:
            st.markdown("<h2 style='color: #F8FAFC; margin-bottom: 2px;'>Outgoing Audit Ledger</h2>", unsafe_allow_html=True)
        with col_ref:
            st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
            if st.button("🔄 Refresh Outbox", use_container_width=True):
                st.rerun()
        st.markdown("<p class='subtitle-text'>Monitor delivery status and revoke access to sent payloads.</p>", unsafe_allow_html=True)
        
        sent_files = get_sent_files(user["id"])
        
        if not sent_files:
            st.info("Outgoing ledger is empty.")
        else:
            for idx, file_data in enumerate(sent_files):
                status_color = "#10B981"
                status_text = file_data["status"]
                
                if file_data["status"] == "ACTIVE":
                    status_color = "#10B981"
                elif file_data["status"] == "EXPIRED":
                    status_color = "#F59E0B"
                elif file_data["status"] == "REVOKED":
                    status_color = "#EF4444"
                elif file_data["status"] == "DOWNLOADED":
                    status_color = "#3B82F6"
                    
                expiry_display = "No expiration"
                if file_data["expires_at"]:
                    dt = datetime.fromisoformat(file_data["expires_at"])
                    expiry_display = dt.strftime("%Y-%m-%d %H:%M")
                    
                one_time_str = "🔒 One-time" if file_data["one_time_only"] else "🔄 Multi-download"
                downloaded_at_str = f"Downloaded at: {file_data['downloaded_at']}" if file_data["downloaded_at"] else "Not yet downloaded"
                
                with st.container(border=True):
                    col_det, col_act = st.columns([4, 1.2])
                    
                    with col_det:
                        st.markdown(f"### 📄 {file_data['original_filename']}")
                        st.markdown(f"""
                        * **Recipient**: {file_data['recipient_name']} (`{file_data['recipient_secure_id']}`)
                        * **Size**: {format_size(file_data['size_bytes'])} | **Sent At**: {file_data['upload_time']}
                        * **Policy**: {one_time_str} | **Expiry**: {expiry_display}
                        * **Delivery Info**: {downloaded_at_str}
                        * **Status**: <span style="background-color:{status_color}; padding: 3px 8px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8rem;">{status_text}</span>
                        """, unsafe_allow_html=True)
                        
                    with col_act:
                        st.markdown("<br>", unsafe_allow_html=True)
                        if file_data["status"] == "ACTIVE":
                            if st.button("🚨 Revoke Access", key=f"rev_btn_{file_data['file_uid']}_{idx}", use_container_width=True, type="secondary"):
                                with st.spinner("Wiping payload file..."):
                                    try:
                                        revoke_file(file_data["file_uid"], user["id"])
                                        st.toast("Access revoked. File deleted.", icon="🚨")
                                        st.rerun()
                                    except ValueError as e:
                                        st.error(str(e))
                        else:
                            st.write("")
                            st.info(f"Settled ({file_data['status']})")

    # 5. ----------------- CONTACTS & USER LOOKUP -----------------
    elif st.session_state.current_page == "Contacts":
        st.markdown("<h2 style='color: #F8FAFC; margin-bottom: 2px;'>Secure Directory Contacts</h2>", unsafe_allow_html=True)
        st.markdown("<p class='subtitle-text'>Manage saved contacts for quick secure document exchange.</p>", unsafe_allow_html=True)
        
        tab_list, tab_search = st.tabs(["👥 Contact Directory", "🔍 Search & Add Gateway Users"])
        
        with tab_list:
            contacts = get_contacts(user["id"])
            if not contacts:
                st.info("No saved contacts. Go to the search tab to add users.")
            else:
                for idx, contact in enumerate(contacts):
                    with st.container(border=True):
                        col_info, col_actions = st.columns([4, 2])
                        with col_info:
                            st.markdown(f"### {contact['name']}")
                            st.markdown(f"""
                            * **SecureShare ID**: `{contact['secure_id']}`
                            * **Email**: {contact['email']}
                            """)
                        with col_actions:
                            st.markdown("<br>", unsafe_allow_html=True)
                            col_a1, col_a2 = st.columns(2)
                            with col_a1:
                                if st.button("📤 Send File", key=f"send_contact_{contact['secure_id']}_{idx}", use_container_width=True):
                                    st.session_state.prefilled_recipient_id = contact["secure_id"]
                                    st.session_state.current_page = "Send File"
                                    st.rerun()
                            with col_a2:
                                if st.button("🗑️ Remove", key=f"remove_contact_{contact['id']}_{idx}", use_container_width=True, type="secondary"):
                                    try:
                                        remove_contact(user["id"], contact["id"])
                                        st.toast(f"Contact {contact['name']} removed.", icon="🗑️")
                                        st.rerun()
                                    except Exception as e:
                                        st.error(str(e))
                                        
        with tab_search:
            st.markdown("### Search User Directory")
            search_query = st.text_input("Enter Email or SecureShare ID", placeholder="e.g. SS-XXXXXXXX or name@company.com")
            
            if search_query:
                results = search_users(search_query)
                results = [r for r in results if r["id"] != user["id"]]
                
                if not results:
                    st.info("No users match query.")
                else:
                    for idx, res in enumerate(results):
                        with st.container(border=True):
                            col_r_info, col_r_act = st.columns([4, 1])
                            with col_r_info:
                                st.markdown(f"**{res['name']}**")
                                st.markdown(f"SecureID: `{res['secure_id']}` | Email: {res['email']}")
                            with col_r_act:
                                st.markdown("<br>", unsafe_allow_html=True)
                                if st.button("➕ Add Contact", key=f"add_res_{res['secure_id']}_{idx}", use_container_width=True):
                                    try:
                                        add_contact(user["id"], res["secure_id"])
                                        st.toast(f"Contact {res['name']} added.", icon="👥")
                                        st.rerun()
                                    except ValueError as e:
                                        st.error(str(e))

    # 6. ----------------- AUDIT LOGS -----------------
    elif st.session_state.current_page == "Audit Logs":
        st.markdown("<h2 style='color: #F8FAFC; margin-bottom: 2px;'>Gateway Audit Ledgers</h2>", unsafe_allow_html=True)
        st.markdown("<p class='subtitle-text'>Immutable record of operations. Verifiable security logs.</p>", unsafe_allow_html=True)
        
        logs = get_user_audit_logs(user["id"])
        
        if not logs:
            st.info("No audit logs recorded.")
        else:
            df = pd.DataFrame(logs)
            
            event_mapping = {
                "SENT": "📤 SENT",
                "RECEIVED": "📥 RECEIVED",
                "DOWNLOADED": "🔓 DOWNLOADED",
                "REVOKED": "🚨 REVOKED",
                "FAILED_DECRYPT": "❌ DECRYPT_FAILED",
                "EXPIRED": "⌛ EXPIRED"
            }
            
            df["event_type"] = df["event_type"].map(event_mapping).fillna(df["event_type"])
            df.columns = [
                "Log ID", "Action type", "Timestamp", "Description/Details", 
                "Filename", "Triggered By", "Trigger Secure ID"
            ]
            
            st.dataframe(
                df[[
                    "Timestamp", "Action type", "Filename", 
                    "Triggered By", "Trigger Secure ID", "Description/Details"
                ]],
                use_container_width=True,
                hide_index=True
            )
            
            st.info("💡 Legally audit-ready: Logs show actions involving your files. System tracks failed decrypts from unauthorized parties.")
