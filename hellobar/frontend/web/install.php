<?php

// Set variables for our request
$shop = $_GET['shop'];
$api_key = "fab7996a89c0ed066f5b413cc5a5fc0e";
$scopes = "read_orders,write_products";
$redirect_uri = "http://localhost:9899/site/gen-token";

// Build install/approval URL to redirect to
$install_url = "https://" . $shop . "/admin/oauth/authorize?client_id=" . $api_key . "&scope=" . $scopes . "&redirect_uri=" . urlencode($redirect_uri);

// Redirect
header("Location: " . $install_url);
die();
