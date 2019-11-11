## appmgr_lookup_plugin

appmgr_lookup_plugin to retrieve really account and password from shterm-appmgr 

## Requirements

1. shterm-agent
2. shterm-appmgr

## Installation

Install the appmgr_lookup_plugin role using the following syntax:

```
$ ansible-galaxy install shterm.appmgr_lookup_plugin
```

## Plugin Usage

- playbook demo

``` yml
- hosts: server1
  roles:
    - role: shterm.appmgr_lookup_plugin         
  vars:
     contents: "{{lookup('appmgr_lookup_plugin',{'appid':'centos', 'query':'username=root;resourceName=host;reason=test;', 'extra':''})}}"
     ansible_ssh_pass: "{{contents.password}}"
     ansible_ssh_user: "{{contents.name}}"
  tasks:
    - debug: msg="the value of foo.txt is {{contents.name}}"
```
- host file demo

```
[demo]
server1 ansible_ssh_host=10.10.20.29 ansible_ssh_pass="{{content.password}}" 
[demo:vars]
content="{{lookup('appmgr_lookup_plugin',{'appid':'centos', 'query':'username=root;resourceName=host;reason=test;', 'extra':''})}}"
```
- command demo

```
ansible 10.10.20.29 -i 10.10.20.29, --playbook-dir ~/.ansible/roles/shterm.appmgr_lookup_plugin/ -u root -e ansible_password="{{lookup('appmgr_lookup_plugin',{'appid':'centos', 'query':'username=root;resourceName=host;reason=test;', 'extra':''}).password}}"  -a 'echo dial'
```

## Plugin Arguments

- **`appid`** (str): Defines the unique ID of the application that is issuing the password request.
- **`query`** (str): Describes the filter criteria for the password retrieval.
- **`extra`** (str):  ExtendField 

## Plugin Return

- > **`dict`**: A dictionary with '`password`' and '`name`'

## License

MIT

## Author Information

- Ding Allen(zjdyms.hz@shterm.com)