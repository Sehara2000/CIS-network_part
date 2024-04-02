#!/bin/bash



############################################## 3.1.1 Ensure system is checked to determine if IPv6 is enabled ##################################################################





# Function to disable IPv6 through GRUB2 configuration
function IPv6_status_reme {
 echo -e "\n\e[33mManual process required [Name - Ensure system is checked to determine if IPv6 is enabled]\n\e[0m"
 echo -e "- Edit /etc/default/grub and add ipv6.disable=1 to the GRUB_CMDLINE_LINUX parameters.\n"
 echo -e "- Run update-grub to update the GRUB2 configuration.\n"
}





########################################### 3.1.2 Ensure wireless interfaces are disabled ###################################################################





# Function to disable wireless interfaces
function wireless_int_check_reme {
    # Check if nmcli command is available
    if command -v nmcli >/dev/null 2>&1; then
        # Turn off all radio devices using nmcli
        nmcli radio all off
        echo -e "\n\e[33mRemediation successful [Name - Ensure wireless interfaces are disabled].\n\e[0m"

    else
        # If nmcli is not available, check for wireless interfaces
        if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
            # Get the module names of wireless drivers
            mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
            # Disable each wireless driver by preventing its loading
            for dm in $mname; do
                echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
            done
        fi
    fi
}





################################################ 3.2.1 Ensure packet redirect sending is disabled (Automated) ###############################################################################





#!/usr/bin/env bash

function packet_re_send_reme {
    # Initialize variables to hold output messages
    l_output=""
    l_output2=""
    
    # Define the parameters to set
    l_parlist="net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0"
    
    # Define search locations for kernel parameter configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
    
    # Define the kernel parameter file
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
    
    # Function to set kernel parameters
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }
    
    # Loop through each parameter in the list and call the function to set it
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done
}






################################################################### 3.2.2 Ensure IP forwarding is disabled ############################################################################################################






function ip_forwrd_dis_reme {

# Initialize variables to hold output messages
l_output=""
l_output2=""

# Define the parameters to set
l_parlist="net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0"

# Define search locations for kernel parameter configuration files
l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"

# Function to set kernel parameters
KPF() {
    # Comment out incorrect parameter(s) in kernel parameter file(s)
    l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
    for l_bkpf in $l_fafile; do
        echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
        sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
    done
    
    # Set correct parameter in a kernel parameter file
    if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
        echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
        echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
    fi
    
    # Set correct parameter in active kernel parameters
    l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
    if [ "$l_krp" != "$l_kpvalue" ]; then
        echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
        sysctl -w "$l_kpname=$l_kpvalue"
        sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
    fi
}

# Function to check IPv6 status and set parameters accordingly
IPV6F_CHK() {
    l_ipv6s=""
    # Find the grub file
    grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)
    if [ -s "$grubfile" ]; then
        ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && l_ipv6s="disabled"
    fi
    if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
       grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
       sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
       sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
        l_ipv6s="disabled"
    fi
    if [ -n "$l_ipv6s" ]; then
        echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
    else
        KPF
    fi
}

# Loop through each parameter in the list and call the function to set it
for l_kpe in $l_parlist; do
    l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
    l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
    if grep -q '^net.ipv6.' <<< "$l_kpe"; then
        l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
        IPV6F_CHK
    else
        l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
        KPF
    fi
done


}





###################################################### 3.3.1 Ensure source routed packets are not accepted ########################################################


function source_rt_pac_reme {
    l_output=""
    l_output2=""
    l_parlist="net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0 net.ipv6.conf.all.accept_source_route=0 net.ipv6.conf.default.accept_source_route=0"
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"

    KPF() {
        # comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters" sysctl -w "$l_kpname=$l_kpvalue" sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    IPV6F_CHK() {
        l_ipv6s=""
        grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)
        if [ -s "$grubfile" ]; then
            ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && l_ipv6s="disabled"
        fi
        if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
        sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
            l_ipv6s="disabled"
        fi
        if [ -n "$l_ipv6s" ]; then
            echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            KPF
        fi
    }

    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        if grep -q '^net.ipv6.' <<< "$l_kpe"; then
            l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
            IPV6F_CHK
        else
            l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
            KPF
        fi
    done

           
}





################################################################### 3.3.2 Ensure ICMP redirects are not accepted ###################################################





function icmp_redirect_reme {

    # Initialize variables
    l_output=""
    l_output2=""
    # List of parameters to set
    l_parlist="net.ipv4.conf.all.accept_redirects=0
    net.ipv4.conf.default.accept_redirects=0
    net.ipv6.conf.all.accept_redirects=0
    net.ipv6.conf.default.accept_redirects=0"
    # Locations to search for sysctl configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf
    /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf
    /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/
    {print $2}' /etc/default/ufw)"

    # Function to handle kernel parameter setting
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Function to check IPv6 settings
    IPV6F_CHK() {
        l_ipv6s=""
        grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)
        if [ -s "$grubfile" ]; then
            ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && l_ipv6s="disabled"
        fi

        if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
        sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
            l_ipv6s="disabled"
        fi

        if [ -n "$l_ipv6s" ]; then
            echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            KPF
        fi
    }

    # Loop through each parameter in the list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        # Check if the parameter is related to IPv6
        if grep -q '^net.ipv6.' <<< "$l_kpe"; then
            l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
            IPV6F_CHK
        else
            l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
            KPF
        fi
    done
}






############################################################## 3.3.3 Ensure secure ICMP redirects are not accepted ########################################################################




function sec_icmp_redirect {

    # Initialize variables
    l_output=""
    l_output2=""
    # List of parameters to set
    l_parlist="net.ipv4.conf.default.secure_redirects=0 net.ipv4.conf.all.secure_redirects=0"

    # Locations to search for sysctl configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
    # File to store kernel parameter settings
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"

    # Function to handle kernel parameter setting
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Loop through each parameter in the list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done
}






################################################################## 3.3.4 Ensure suspicious packets are logged ###################################################################################






function packt_log_reme {

    # Initialize variables
    l_output=""
    l_output2=""
    # List of parameters to set
    l_parlist="net.ipv4.conf.all.log_martians=1 net.ipv4.conf.default.log_martians=1"
    # Locations to search for sysctl configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
    # File to store kernel parameter settings
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"

    # Function to handle kernel parameter setting
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"

        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$"$l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"

        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Loop through each parameter in the list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done

}





########################################################## 3.3.5 Ensure broadcast ICMP requests are ignored  ###########################################################################################





function brodcst_icmp_reme {
    # Initialize variables
    l_output=""
    l_output2=""
    # List of parameters to set
    l_parlist="net.ipv4.icmp_echo_ignore_broadcasts=1"
    # Locations to search for sysctl configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
    # File to store kernel parameter settings
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"

    # Function to handle kernel parameter setting
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Loop through each parameter in the list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done
}




############################################################################# 3.3.6 Ensure bogus ICMP responses are ignored #################################################################################





function bogus_icmp_reme {

    # Initialize variables
    l_output=""
    l_output2=""

    # List of parameters to set
    l_parlist="icmp_ignore_bogus_error_responses=1"

    # Locations to search for sysctl configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"

    # File to store kernel parameter settings
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"

    # Function to handle kernel parameter setting
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Loop through each parameter in the list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done
}





############################################################################# 3.3.7 Ensure Reverse Path Filtering is enabled ###############################################################################






function rvrs_path_filtr_reme {

    # Initialize variables to store output
    l_output=""
    l_output2=""

    # List of kernel parameters to set
    l_parlist="net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1"

    # Locations to search for sysctl configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"

    # File to store kernel parameter settings
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"

    # Function to handle kernel parameter setting
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Loop through each parameter in the list and call KPF function
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done

}





############################################################################### 3.3.8 Ensure TCP SYN Cookies is enabled  ###################################################################################



function tcp_syn_cookies_reme {

    # Initialize variables
    l_output=""
    l_output2=""

    # List of kernel parameters to be configured
    l_parlist="net.ipv4.tcp_syncookies=1"

    # Locations to search for kernel parameter configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    # File to write kernel parameter configurations to
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"

    # Function to update kernel parameter configurations
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Loop through the list of kernel parameters
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done
}





####################################################################### 3.3.9 Ensure IPv6 router advertisements are not accepted #############################################################################################





function IPv6_router_ad_reme {
    #!/bin/bash

    # Initialize variables
    l_output=""
    l_output2=""
    l_parlist="net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0"
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"

    KPF() {
        # Function to comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    IPV6F_CHK() {
        # Function to check IPv6 settings
        l_ipv6s=""
        grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)
        if [ -s "$grubfile" ]; then
            ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && l_ipv6s="disabled"
        fi

        if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
        sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
            l_ipv6s="disabled"
        fi

        if [ -n "$l_ipv6s" ]; then
            echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            KPF
        fi
    }

    # Loop through each parameter in the parameter list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        if grep -q '^net.ipv6.' <<< "$l_kpe"; then
            l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
            IPV6F_CHK
        else
            l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
            KPF
        fi
    done


}





################################################################################ 3.4.1 Ensure DCCP is disabled ###############################################################################################






function dccp_disbl_reme {


    # Set module name
    l_mname="dccp"

    # Check if module can be loaded
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)'; then
        echo -e " - Setting module: \"$l_mname\" to be not loadable"
        echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
    fi

    # Unload the module if it is already loaded
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo -e " - Unloading module \"$l_mname\""
        modprobe -r "$l_mname"
    fi

    # Check if module is blacklisted
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo -e " - Deny listing \"$l_mname\""
        echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi


}







##################################################################### 3.4.2 Ensure SCTP is disabled  #########################################################################################################




function sctp_disbl_reme {

# Set module name
l_mname="sctp"

# Check if module can be loaded
if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)'; then
    echo -e " - Setting module: \"$l_mname\" to be not loadable"
    echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
fi

# Unload the module if it is already loaded
if lsmod | grep "$l_mname" > /dev/null 2>&1; then
    echo -e " - Unloading module \"$l_mname\""
    modprobe -r "$l_mname"
fi

# Check if module is blacklisted
if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
    echo -e " - Deny listing \"$l_mname\""
    echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
fi

}





########################################################### 3.4.3 Ensure RDS is disabled ###################################################################################




function rds_disbl_reme {

    # Set module name
    l_mname="rds"

    # Check if module can be loaded
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)'; then
        echo -e " - Setting module: \"$l_mname\" to be not loadable"
        echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
    fi

    # Unload the module if it is already loaded
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo -e " - Unloading module \"$l_mname\""
        modprobe -r "$l_mname"
    fi

    # Check if module is blacklisted
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo -e " - Deny listing \"$l_mname\""
        echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi

}





################################################################### 3.4.4 Ensure TIPC is disabled ###################################################################################




function tipc_disbl_reme {
    # Set module name
    l_mname="tipc"

    # Check if module can be loaded
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)'; then
        echo -e " - Setting module: \"$l_mname\" to be not loadable"  # Print message indicating that module is set to be not loadable
        echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf  # Set module to be not loadable
    fi

    # Unload the module if it is already loaded
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo -e " - Unloading module \"$l_mname\""  # Print message indicating unloading of the module
        modprobe -r "$l_mname"  # Unload the module
    fi

    # Check if module is blacklisted
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo -e " - Deny listing \"$l_mname\""  # Print message indicating denial of listing for the module
        echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf  # Blacklist the module
    fi

}






################################################################# 3.5.1.1 Ensure ufw is installed #################################################################################





function ufw_ins_reme {



}







































































































































































































































































































































































































































































































