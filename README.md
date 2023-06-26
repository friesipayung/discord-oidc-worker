# Discord OIDC Worker for Firebase Auth

This is a Cloudflare Worker that implements
the [Discord OAuth2](https://discord.com/developers/docs/topics/oauth2#shared-resources-oauth2-scopes) flow for Firebase
Auth.
Add `.well-known/openid-configuration` to your domain and point it to this worker.

## Requirements

- Create a new Discord application at https://discord.com/developers/applications
- Create a new Firebase project at https://console.firebase.google.com/
- Create a new Cloudflare worker at https://workers.cloudflare.com/

## Configuration

### Firebase

- Add new provider OpenID Connect on Firebase
- Add Client ID and Client Secret from Discord application
- Add `https://<your-domain>/.well-known/openid-configuration` as the discovery document URL

### Discord

- Add firebase redirect URL to OAuth2 redirect URIs

### Cloudflare Worker

- Create a new KV namespace

## How to use

- Rename `config.sample.json` to `config.json`
- Change the values in `config.json` to your own
- Run `npm install` to install dependencies
- Run `npx wrangler publish` to publish the worker to Cloudflare


## License
This project is licensed under the MIT License 

