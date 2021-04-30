## Jolt Twitch Wordpress Plugin

A plugin to connect to Twitch's EventSub subscriptions and output the online status of a streaming account through the Wordpress API.

While what this does is very specific to the usecase at Jolt Radio, the subscription flow for Twitch could be useful for anyone looking to interact with Twitch via PHP/Wordpress.

#### Usage

Place the plugin folder in your Wordpress plugin folder, activate it, and then configure it via the options. Once configured, online status will be available at `example.com/wp/v2/jolt-twitch/` and the subscription response will be available at `example.com/wp/v2/jolt-twitch/event-callback`.