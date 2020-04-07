# VIISP Auth Handler

This is nodejs module that helps to integrate with Lithuanian E-Government Gateway
VIISP - "Valstybės Informacinių Išteklių Sąveikumo Platforma"

## Usage

yarn add viisp-nodejs-auth-handler

```

import { ViispAuthClient } from 'viisp-nodejs-auth-handler';


(async function () {
  // initialize viisp auth handler
  const handler = await ViispAuthClient.init({
    cert: {
      // key certificate that was issued for you organization by LT E-Government or test certifacate
      key: process.env.VIISP_KEY_PATH,
      // certificate that was issued for you organization by LT E-Government or test certifacate
      cert: process.env.VIISP_CERT_PATH,
    },
  });

  // get ticket from the VIISP SOAP API using handler
  // where process.env.VIISP_AUTH_POSTBACK_URL is your callback url from which you redirect to the frontend
  cosnt ticket = await ViispAuthClient.getTicket(proces.env.VIISP_AUTH_POSTBACK_URL);
  // ticket = 2d6c830f-3a3e-4c56-9c51-a56a33b63741


  //... perform post to your backed from frontend with the provided ticket


  // in indentification request, perform getIdentity with the provided ticket
  const identity = await ViispAuthClient.getIdentity(ticket);
  // identity = {
  //   name: ...,
  //   surname: ...,
  //   birthdate: ...,
  //   sex: ...,
  // }
})()

```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sagahead-io/viisp-nodejs-auth-handler/issues. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the viisp-nodejs-auth-handler project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/sagahead-io/viisp-nodejs-auth-handler/blob/master/CODE_OF_CONDUCT.md).