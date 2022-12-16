# lua-resty-session

**lua-resty-session** is a secure, and flexible session library for OpenResty.

## API

### Static Methods

- session.init
- session.new
- session.open
- session.start
- session.logout
- session.destroy

### Instance Methods

- session:open
- session:restore
- session:persist
- session:set
- session:get
- session:set_subject
- session:get_subject
- session:set_audience
- session:get_audience
- session.info:set
- session.info:get
- session.info:save
- session:save
- session:touch
- session:refresh
- session:logout
- session:destroy
- session:close
- session:hide


## License

`lua-resty-session` uses two clause BSD license.

```
Copyright (c) 2014 – 2022 Aapo Talvensaari, 2022 Samuele Illuminati
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
```
