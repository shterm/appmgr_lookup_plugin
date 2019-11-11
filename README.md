## shterm_reset_acm

shterm_reset_acm lookup plugin to retrieve really account and password from shterm appmgr 

## Requirements

1. shterm-agent
2. shterm-appmgr

## Installation

Install the Conjur role using the following syntax:

```
$ ansible-galaxy install shterm.shterm_reset_acm
```

## Plugin Usage

- playbook demo

``` yml
- hosts: server1
  roles:
    - role: zjdym.reset_acm         
  vars:
     contents: "{{lookup('reset_acm_variable',{'appid':'centos', 'query':'username=root;resourceName=host;reason=test;', 'extra':''})}}"
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
content="{{lookup('reset_acm_variable',{'appid':'centos', 'query':'username=root;resourceName=host;reason=test;', 'extra':''})}}"
```
- command demo

```
ansible 10.10.20.29 -i 10.10.20.29, --playbook-dir ~/.ansible/roles/shterm.shterm_reset_acm/ -u root -e ansible_password="{{lookup('reset_acm_variable',{'appid':'centos', 'query':'username=root;resourceName=host;reason=test;', 'extra':''}).password}}"  -a 'echo dial'
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