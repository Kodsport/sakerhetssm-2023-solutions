

# first fix .tfvars
# admin_ssh_keys = [ 1234 ]
# do_token = "dop_v1_blabla"

terraform apply -var-file=".tfvars"

sleep 60 # wait for server 


ansible-playbook -i ./terraform_output/inventory.yml playbook.yml -u root

