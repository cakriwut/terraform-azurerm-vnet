#------------------------
# Local declarations
#------------------------
locals {
  resource_group_name = element(coalescelist(data.azurerm_resource_group.rgrp.*.name, azurerm_resource_group.rg.*.name, [""]), 0)
  location            = element(coalescelist(data.azurerm_resource_group.rgrp.*.location, azurerm_resource_group.rg.*.location, [""]), 0)
  if_ddos_enabled     = var.create_ddos_plan ? [{}] : []

  firewall_subnet =  var.firewall_subnet_address_prefix != null ? { "firewall_subnet" = {       
      subnet_name = "AzureFirewallSubnet"
      subnet_address_prefix  = var.firewall_subnet_address_prefix
      service_endpoints = var.firewall_service_endpoints
   }} : {} 

  gateway_subnet =  var.gateway_subnet_address_prefix != null ? { "gateway_subnet" = {       
        subnet_name = "GatewaySubnet"
        subnet_address_prefix  = var.gateway_subnet_address_prefix
        service_endpoints = ["Microsoft.Storage"]
    }} : {}

  subnets = merge({
     for subnet_tier, value in var.subnets : subnet_tier => value
   }, local.firewall_subnet, local.gateway_subnet)

  subnets_nsgs = flatten([
    for key,subnet in local.subnets : [
         for rule in concat(lookup(subnet, "nsg_inbound_rules", []), lookup(subnet, "nsg_outbound_rules", [])) : 
            {
              keyname                    = "${rule[2] == "" ? "Inbound" : rule[2]}_${rule[1]}"
              subnet_nsg_name            = lower("nsg_${key}_in")
              key                        = key
              subnet_name                = subnet.subnet_name
              name                       = rule[0] == "" ? "Default_Rule" : rule[0]
              priority                   = rule[1]
              direction                  = rule[2] == "" ? "Inbound" : rule[2]
              access                     = rule[3] == "" ? "Allow" : rule[3]
              protocol                   = rule[4] == "" ? "Tcp" : rule[4]
              source_port_range          = "*"
              destination_port_range     = rule[5] == "" ? "*" : rule[5]
              source_address_prefix      = rule[6] == "" ? element(subnet.subnet_address_prefix, 0) : rule[6]
              destination_address_prefix = rule[7] == "" ? element(subnet.subnet_address_prefix, 0) : rule[7]
              description                = "${rule[2]}_Port_${rule[5]}"
            }
       ]
  ])
}


data "azurerm_resource_group" "rgrp" {
  count = var.create_resource_group == false ? 1 : 0
  name  = var.resource_group_name
}

resource "azurerm_resource_group" "rg" {
  count    = var.create_resource_group ? 1 : 0
  name     = var.resource_group_name
  location = var.location
  tags     = merge({ "Name" = format("%s", var.resource_group_name) }, var.tags, )
}

#-------------------------------------
# VNET Creation - Default is "true"
#-------------------------------------

resource "azurerm_virtual_network" "vnet" {
  name                = var.vnetwork_name
  location            = local.location
  resource_group_name = local.resource_group_name
  address_space       = var.vnet_address_space
  dns_servers         = var.dns_servers
  tags                = merge({ "Name" = format("%s", var.vnetwork_name) }, var.tags, )

  dynamic "ddos_protection_plan" {
    for_each = local.if_ddos_enabled

    content {
      id     = azurerm_network_ddos_protection_plan.ddos[0].id
      enable = true
    }
  }
}

#--------------------------------------------
# Ddos protection plan - Default is "false"
#--------------------------------------------

resource "azurerm_network_ddos_protection_plan" "ddos" {
  count               = var.create_ddos_plan ? 1 : 0
  name                = var.ddos_plan_name
  resource_group_name = local.resource_group_name
  location            = local.location
  tags                = merge({ "Name" = format("%s", var.ddos_plan_name) }, var.tags, )
}

#-------------------------------------
# Network Watcher - Default is "true"
#-------------------------------------
resource "azurerm_resource_group" "nwatcher" {
  count    = var.create_network_watcher != false ? 1 : 0
  name     = "NetworkWatcherRG"
  location = local.location
  tags     = merge({ "Name" = "NetworkWatcherRG" }, var.tags, )
}

resource "azurerm_network_watcher" "nwatcher" {
  count               = var.create_network_watcher != false ? 1 : 0
  name                = "NetworkWatcher_${local.location}"
  location            = local.location
  resource_group_name = azurerm_resource_group.nwatcher.0.name
  tags                = merge({ "Name" = format("%s", "NetworkWatcher_${local.location}") }, var.tags, )
}


resource "azurerm_subnet" "snet" {
  for_each                                       = local.subnets
  name                                           = each.value.subnet_name
  resource_group_name                            = local.resource_group_name
  virtual_network_name                           = azurerm_virtual_network.vnet.name
  address_prefixes                               = each.value.subnet_address_prefix
  service_endpoints                              = lookup(each.value, "service_endpoints", [])
  enforce_private_link_endpoint_network_policies = lookup(each.value, "enforce_private_link_endpoint_network_policies", null)
  enforce_private_link_service_network_policies  = lookup(each.value, "enforce_private_link_service_network_policies", null)

  dynamic "delegation" {
    for_each = lookup(each.value, "delegation", {}) != {} ? [1] : []
    content {
      name = lookup(each.value.delegation, "name", null)
      service_delegation {
        name    = lookup(each.value.delegation.service_delegation, "name", null)
        actions = lookup(each.value.delegation.service_delegation, "actions", null)
      }
    }
  }
}

#-----------------------------------------------
# Network security group - Default is "false"
#-----------------------------------------------
resource "azurerm_network_security_group" "nsg" {
  for_each            = var.subnets
  name                = lower("nsg_${each.key}_in")
  resource_group_name = local.resource_group_name
  location            = local.location
  tags                = merge({ "ResourceName" = lower("nsg_${each.key}_in") }, var.tags, )

}


resource "azurerm_network_security_rule" "nsg-rule" {
   for_each = {
     for  rule in local.subnets_nsgs : "${rule.keyname}_${rule.subnet_name}" => rule
   }
  
    resource_group_name   = local.resource_group_name
    network_security_group_name = azurerm_network_security_group.nsg[each.value.key].name

    name                  = each.value.name
    priority              = each.value.priority
    direction             = each.value.direction
    access                = each.value.access
    protocol              = each.value.protocol
    source_port_range    = each.value.source_port_range     
    destination_port_range = each.value.destination_port_range 

    source_address_prefix = each.value.source_address_prefix
    destination_address_prefix = each.value.destination_address_prefix
    
    description                = each.value.description
}


resource "azurerm_subnet_network_security_group_association" "nsg-assoc" {
  for_each                  = var.subnets
  subnet_id                 = azurerm_subnet.snet[each.key].id
  network_security_group_id = azurerm_network_security_group.nsg[each.key].id
}

