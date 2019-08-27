from quay.io/jkremser/openshift-spark:2.4.0

USER root

COPY requirements.txt ./

RUN yum install  -y https://centos7.iuscommunity.org/ius-release.rpm

RUN yum update -y

RUN yum install -y python36u python36u-libs python36u-devel python36u-pip

RUN python3.6 -m pip install --upgrade pip

RUN python3.6 -m pip install -r requirements.txt