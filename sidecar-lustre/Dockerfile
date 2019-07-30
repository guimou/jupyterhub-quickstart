FROM centos:7

RUN yum update -y

RUN yum install -y https://downloads.whamcloud.com/public/lustre/latest-2.12-release/el7/client/RPMS/x86_64/kmod-lustre-client-2.12.2-1.el7.x86_64.rpm
RUN yum install -y https://downloads.whamcloud.com/public/lustre/latest-2.12-release/el7/client/RPMS/x86_64/lustre-client-2.12.2-1.el7.x86_64.rpm

CMD trap : TERM INT; (while true; do sleep 1000; done) & wait
