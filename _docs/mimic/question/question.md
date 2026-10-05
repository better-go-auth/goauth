- why is a random string better than a ulid, for id purposes




-----------


- remove sesssion.Hashedtoken, and use just the token
- why string generation, 
- drop password from user table all together


- what things can we move form compat to the main codebase

- what is the use of activeTeamId
- make the passwords an interface

- what is use of common/types/ RawBodyMetaKey = "goauth.rawBody" and Transform, Document Operation and etc

what is use of src/sessions and where can it be moved

> Done: `src/sessions` Manager (create/get/refresh/delete/list, sliding expiry, rememberMe, freshAge,
> secondary storage with better-auth key layout, cleanup), Resolver middlewares, `GET|POST /get-session`
> (compat mode only). Legacy `/login`/`/refresh` are not yet rewired onto the Manager (step 3b, v2 branch).



--------------------


what is the use of the new

Sessions, SessionResolver and cookeis functions in goauth




-----------

make the fullname as optional 


- fix the length , and remove length constraints and make it text