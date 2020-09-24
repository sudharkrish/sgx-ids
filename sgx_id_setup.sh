#Source->https://github.com/cloud-security-research/sgx-ids
#Once the machine comes up execute the following commands. 
#Note: These commands need to be executed on every boot

mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
ulimit -l unlimited  # in case limits.conf doesn't help
sudo sysctl vm.mmap_min_addr=0
