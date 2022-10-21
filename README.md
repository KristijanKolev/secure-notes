# secure-notes
**Ann app for storing and sharing sensitive information**

A user can create notes whose content is kept encrypted and can be viewed only by someone who has a specific note's access key. The encryption of the content is done using Fernet with a user-defined password as an encryption key, meaning the content will remain secure in the event of a database leak.



## Implementation

**Backend:** REST API built with django-rest-framework

**Frontend:** Angular <sup>*pending</sup>
