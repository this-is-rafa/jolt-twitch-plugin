<?php
/*
Plugin Name: Jolt Twitch
Plugin URI: http://joltradio.org
Description: Pull twitch status and serve through API
Version: 0.3
Author: Rafa
Author URI: rrdesign.us
Text Domain: jolt-twitch
License: GPLv3 or later
License URI: http://www.gnu.org/licenses/gpl-3.0.html

Copyright © 2021 Rafa

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

*/

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Get an Oauth token from Twitch to subscribe to events.
 * @return string $token is our token from Twitch, encoded in base64.
 */
function jolt_twitch_getToken() {
  $token = get_transient('jolt_twitch_token');

  if (false !== $token) {
    return $token;
  }

  $twitchClientId = get_option('jolt_twitchClientId', '0');
  $twitchSecret = get_option('jolt_twitchSecret', 'change this secret key');
  $oauthUrl = 'https://id.twitch.tv/oauth2/token';

  $payload = [
    'client_id' => $twitchClientId,
    'client_secret' => $twitchSecret,
    'grant_type' => 'client_credentials'
  ];

  $headers = [
    'Content-Type' => 'application/json'
  ];

  $response = wp_remote_post($oauthUrl, [
    'headers' => $headers,
    'body' => wp_json_encode($payload),
    'timeout' => 10
  ]);

  if (is_wp_error($response)) {
    error_log('Attempt to get token has failed.');
    return false;
  }

  $body = wp_remote_retrieve_body($response);

  $body = json_decode($body, true);

  if ($body === false || !isset($body['access_token'])) {
    return false;
  }

  $token = base64_encode($body['access_token']);

  set_transient( 'jolt_twitch_token', $token, $body['expires_in'] - 30 );
	return $token;
}

/**
 * Subscribe to the Twitch events we want: when we start broadcasting
 * and when we stop, checking to see we're not already subscribed.
 * @return void
 */
function jolt_twitch_subscribe_flow() {
  if ( get_option('jolt_twitchTesting') === 'on') {
    return false;
  }

  $webhookUrl = 'https://api.twitch.tv/helix/eventsub/subscriptions';

  $token = jolt_twitch_getToken();

  if (false === $token)
    return null;

  //Check if we're already subscribed
  $currentSubs = jolt_twitch_getSubs();
  if ( sizeof($currentSubs) === 2 ) {
    return null;
  }

  $twitchClientId = get_option('jolt_twitchClientId', '0');
  $twitchSubSecret = get_option('jolt_twitchSubSecret', 'change this secret key');

  jolt_twitch_subEvent('stream.online', $twitchClientId, $twitchSubSecret, $token, $webhookUrl);
  jolt_twitch_subEvent('stream.offline', $twitchClientId, $twitchSubSecret, $token, $webhookUrl);
}

/**
 * Check if we are subscribed to our events, so as not to subscribe again.
 * @return bool|array false if there are no subs, otherwise an array of $allSubs.
 */
function jolt_twitch_getSubs() {
  $token = jolt_twitch_getToken();

  if (false === $token)
    return false;

  $subscriptionsUrl = 'https://api.twitch.tv/helix/eventsub/subscriptions?status=enabled';

  $twitchClientId = get_option('jolt_twitchClientId', '0');

  $headers = [
    'Client-ID' => $twitchClientId,
    'Authorization' => 'Bearer ' . base64_decode($token)
  ];

  $response = wp_remote_get($subscriptionsUrl, [
    'headers' => $headers
  ]);

  $body = wp_remote_retrieve_body($response);

  $body = json_decode($body, true);

  if (isset($body['data'])) {
    $allSubs = [];
    
    foreach ($body['data'] as $sub) {
      $type = $sub['type'];
      $id = $sub['id'];

      $allSubs[$type] = $id;
    }

    return $allSubs;
  }

  return false;
}

/**
 * Subscribe to a Twitch event.
 * @param string $type of Twitch event (https://dev.twitch.tv/docs/eventsub/eventsub-subscription-types)
 * @param int $id Your Twitch Client ID
 * @param string $secret Your Twitch secret key
 * @param string $token retrieved by jolt_twitch_getToken()
 * @param string $url for Twicth EventSubs
 * @return bool False if the subscription fails, else true.
 */
function jolt_twitch_subEvent($type, $id, $secret, $token, $url) {
  $broadcasterUserId = get_option('jolt_twitchUserId', '0');

  $headers = [
    'Client-ID' => $id,
    'Authorization' => 'Bearer ' . base64_decode($token),
    'Content-Type' => 'application/json',
  ];

  $payload = [
    'type' => $type,
    'version' => 1,
    'condition' => [
      'broadcaster_user_id' => $broadcasterUserId
    ],
    'transport' => [
      'method' => 'webhook',
      'callback' => get_site_url() . '/wp-json/wp/v2/jolt-twitch/event-callback',
      'secret' => $secret
    ]
  ];

  $response = wp_remote_post($url, [
    'headers' => $headers,
    'body' => json_encode($payload),
    'timeout' => 10
  ]);

  if (is_wp_error($response)) {
    error_log('Attempt to subscribe has failed: ' . $type);
    return false;
  }

  $body = wp_remote_retrieve_body($response);

  $body = json_decode($body, true);

  return true;
}

/**
 * Takes any current subscriptions as an input and ubsubscribes them.
 * @param array $subscriptions returned from jolt_twitch_getSubs()
 * @return void
 */
function jolt_twitch_unsubEvents($subscriptions) {
  if (empty($subscriptions))
    return false;

  $token = jolt_twitch_getToken();
  $twitchClientId = get_option('jolt_twitchClientId', '0');

  $headers = [
    'Client-ID' => $twitchClientId,
    'Authorize' => 'Bearer ' . base64_decode($token)
  ];

  $url = 'https://api.twitch.tv/helix/eventsub/subscriptions?id=';

  foreach ($subscriptions as $sub) {
    $deleteUrl = $url . $sub;
    wp_remote_request($deleteUrl, ['method' => 'DELETE']);
  }
}

/**
 * Checks our Twitch subscriptions, unsubscribes from all of them, and
 * then deletes our current Twitch token.
 * @return void
 */
function jolt_twitch_unsubAllEvents() {
  $subs = jolt_twitch_getSubs();
  jolt_twitch_unsubEvents($subs);
  delete_transient('jolt_twitch_token');
}

/**
 * Handles our response to Twitch after subscribing to an event, and if the
 * subscription is succesful will update our endpoint with our subscription status.
 * 
 * Twitch will immediately send a POST request back to us after subscribing.
 * In it there will be data that needs to be combined and hashed together
 * with our own Twitch secret key and served as a response to the POST request. This
 * confirmation also prevents fradulent subscriptions.
 * 
 * If our subscription is valid, we go ahead and call jolt_twitch_setStatus() to update
 * our endpoint.
 * @return void
 */
function jolt_twitch_eventResponse() {
  if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
    $isVerified = false;
    
    $headers = getallheaders();
    $headers = array_change_key_case($headers, CASE_LOWER);

    if (isset($headers['twitch-eventsub-message-signature'])) {
      $signature = $headers['twitch-eventsub-message-signature'];
      $messageId = $headers['twitch-eventsub-message-id'];
      $timeStamp = $headers['twitch-eventsub-message-timestamp'];
    } else {
      status_header(403);
      error_log('No signature header.');
      return;
    }
    
    if (isset($signature)) {
      $twitchSubSecret = get_option('jolt_twitchSubSecret', '0');
      $data = file_get_contents("php://input");
      $hmacMessage = $messageId . $timeStamp . $data;

      $hash = 'sha256=' . hash_hmac('sha256', $hmacMessage, $twitchSubSecret);
      $isVerified = $hash === $signature;
    }

    if (!$isVerified) {
      status_header(403);
      error_log('isVerified is false. returning error.');
      return;
    }

    $data = json_decode($data, true);

    $challenge = isset($data['challenge']) ? $data['challenge'] : null;
    $statusLive = isset($data['subscription']['type']) ? $data['subscription']['type'] :null;

    if (isset($challenge)) {
      echo $challenge;
      return;
    }

    if (isset($statusLive)) {
      if ($statusLive === 'stream.online') {
        jolt_twitch_setStatus(true);
      } elseif ($statusLive === 'stream.offline') {
        jolt_twitch_setStatus(false);
      }
    }

    return;
  }
}

/**
 * Update the live status of our Twitch stream.
 * 
 * Using WP's update_option we store our live status, recieved from
 * our subscriptions, in the WP database. This way we can serve it later
 * as an API response.
 * @param bool $liveStatus
 * @return bool true if the status was updated, otherwise false.
 */
function jolt_twitch_setStatus($liveStatus) {
  $status = [
    'live' => $liveStatus
  ];

  return update_option('jolt_twitchStatus', $status);
}

function jolt_twitch_getStatus() {
  if ( get_option('jolt_twitchForceLive') === 'on') {
    return ['live' => true];
  }

  return get_option('jolt_twitchStatus');
}

/**
 * Create the plugin settings menu and page in WP backend
 * @return void
 */
function jolt_twitch_addSettingsPage() {
  add_options_page(
    'Jolt Twitch',
    'Jolt Twitch',
    'manage_options',
    'jolt-twitch',
    'jolt_twitch_createAdminPage'
  );
}

/**
 * Populate the plugin settings page in WP backend
 * @return void
 */
function jolt_twitch_createAdminPage() { 
  if (!current_user_can('manage_options')) {
    wp_die('Unauthorized user');
  }

  $twitchClientId = get_option('jolt_twitchClientId', 'none');
  $twitchUserId = get_option('jolt_twitchUserId', 'none');
  $twitchSecret = get_option('jolt_twitchSecret', 'change this secret key');
  $twitchSubSecret = get_option('jolt_twitchSubSecret', 'change this secret key');
  $twitchForceLive = get_option('jolt_twitchForceLive');

  if ( !isset( $_POST['jolt_twitch_settings_noncer'] ) 
    || !wp_verify_nonce( $_POST['jolt_twitch_settings_noncer'], 'jolt_twitch' ) 
  ) {
    print 'Sorry, your nonce did not verify.';
  } else {

    if ( isset($_POST['jolt_twitchClientId']) ) {
      $twitchClientId = $_POST['jolt_twitchClientId'];
      $twitchClientId= trim($twitchClientId);
      $twitchClientId = strip_tags($twitchClientId);
      update_option('jolt_twitchClientId', $twitchClientId);
    }

    if ( isset($_POST['jolt_twitchUserId']) ) {
      $twitchUserId = $_POST['jolt_twitchUserId'];
      $twitchUserId = trim($twitchUserId);
      $twitchUserId = strip_tags($twitchUserId);
      update_option('jolt_twitchUserId', $twitchUserId);
    }

    if ( isset($_POST['jolt_twitchSecret']) ) {
      $twitchSecret = $_POST['jolt_twitchSecret'];
      $twitchSecret = trim($twitchSecret);
      $twitchSecret = strip_tags($twitchSecret);
      update_option('jolt_twitchSecret', $twitchSecret);
    }

    if ( isset($_POST['jolt_twitchSubSecret']) ) {
      $twitchSubSecret = $_POST['jolt_twitchSubSecret'];
      $twitchSubSecret = trim($twitchSubSecret);
      $twitchSubSecret = strip_tags($twitchSubSecret);
      update_option('jolt_twitchSubSecret', $twitchSubSecret);
    }

    if ( isset($_POST['jolt_twitchForceLive']) ) {
      update_option('jolt_twitchForceLive', 'on');
      $twitchForceLive = 'on';
    } else {
      update_option('jolt_twitchForceLive', 'off');
      $twitchForceLive = 'off';
    }

    if ( isset($_POST['jolt_twitchUnsubscribeAllEvents']) ) {
      jolt_twitch_unsubAllEvents();
    }

    if ( isset($_POST['jolt_twitchSubscribeAllEvents']) ) {
      jolt_twitch_subscribe_flow();
    }
  }

  ?>
  <div>
    <h2>Jolt Twitch</h2>
    <h3>Credentials</h3>
    <form method="post">
      <p>
        <label>
          Twitch Client ID
          <input name="jolt_twitchClientId" type="text" value="<?= $twitchClientId ?>" />
        </label>
      </p>
      <p>
        <label>
          User ID for stream
          <input name="jolt_twitchUserId" type="text" value="<?= $twitchUserId ?>" />
        </label>
      </p>
      <p>
        <label>
          Secret Key
          <input name="jolt_twitchSecret" type="text" value="<?= $twitchSecret ?>" />
        </label>
      </p>
      <p>
        <label>
          Sub Secret
          <input name="jolt_twitchSubSecret" type="text" value="<?= $twitchSubSecret ?>" />
        </label>
      </p>
      <p>
        <label>
          Set status to 'live' for testing.
          <input name="jolt_twitchForceLive" type="checkbox" <?= $twitchForceLive === 'on' ? 'checked' : ''?>  />
        </label>
      </p>
      <?php wp_nonce_field( 'jolt_twitch', 'jolt_twitch_settings_noncer' ); ?>
      <input type="Submit" value="Save" class="button button-primary button-large">
    </form>
    <form method="post">
      <?php wp_nonce_field( 'jolt_twitch', 'jolt_twitch_settings_noncer' ); ?>
      <input type="hidden" name="jolt_twitchUnsubscribeAllEvents" value="true" />
      <input type="Submit" value="Unsubscribe All Events" class="button button-primary button-large">
    </form>
    <form method="post">
      <?php wp_nonce_field( 'jolt_twitch', 'jolt_twitch_settings_noncer' ); ?>
      <input type="hidden" name="jolt_twitchSubscribeAllEvents" value="true" />
      <input type="Submit" value="Subscribe All Events" class="button button-primary button-large">
    </form>
  </div>

<?php }

/**
 * WP plugin activation routine.
 * 
 * We set our testing status off, the live status off in case either
 * of these were left on due to unforseen circumstances, and we schedule
 * our WP cronjob to check our subscriptions hourly.
 * @return void
 */
function jolt_twitch_activation() {
  update_option('jolt_twitchTesting', 'off');
  update_option('jolt_twitchStatus', ['live' => false]);

  if ( !wp_next_scheduled('jolt_twitch_update') ) {
    wp_schedule_event(time(), 'hourly', 'jolt_twitch_update');
  }
}

/**
 * WP plugin deactivation routine.
 * 
 * Clears the WP cronjob and ubsubscribes from any Twitch events still
 * outstanding.
 * @return void
 */
function jolt_twitch_deactivation() {
  wp_clear_scheduled_hook('jolt_twitch_update');
  jolt_twitch_unsubAllEvents();
}

add_action('admin_menu', 'jolt_twitch_addSettingsPage');

add_action( 'rest_api_init', function () {
	register_rest_route('wp/v2', '/jolt-twitch', [
		'methods' => 'GET',
		'callback' => 'jolt_twitch_getStatus',
   ]);
  
  register_rest_route('wp/v2', '/jolt-twitch/event-callback', [
		'methods' => 'POST',
		'callback' => 'jolt_twitch_eventResponse',
  ]);
} );

add_action('jolt_twitch_update', 'jolt_twitch_subscribe_flow', 10, 2);
 

register_activation_hook(__FILE__, 'jolt_twitch_activation');
register_deactivation_hook(__FILE__, 'jolt_twitch_deactivation');