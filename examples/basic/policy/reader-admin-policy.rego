package s3

   # Admins can perform any operation on any bucket.
   allow {
       input.groups[_] == "admin"
   }

   # Readers can only perform read actions on any bucket.
   allow {
       input.groups[_] == "reader"
       input.action in {
           "GetObject",
           "HeadObject",
           "ListObjects",
           "ListObjectsV2",
           "GetObjectTagging",
       }
   }
