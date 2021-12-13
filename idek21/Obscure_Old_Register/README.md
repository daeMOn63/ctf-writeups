# Obscure Old Register

We get a hint on a Talon register: 
https://m.media-amazon.com/images/I/81qEQFUgFmL._AC_SS350_.jpg

Given the picture above, and the challenge input:
```
7-1 4-1 4-2 8-1 1 1 1 9 1 8-1 7-1 10 5-2 1 1 1 2 7-1 5-2 1 1 1 5-1 8-2 1 5-2 14 1 1 1 7-2 16-1 14 15 1 1 1 15 11 1 1 1 9 1 8-1 4-2 1 1 1 18-1 11 16-1 1 1 1 16-1 14 4-2 1 1 1 1 1 1 1 14 3 13 7-1 12-1 15 1 1 1 11 13 1 1 1 2 4-2 1 1 1 1 10 10 11 18-1 4-2 4-1 1 1 1 1 15 1 1 1 9 4-2 1 1 1 4-2 6 4-2 6 4-2 6 1 1 1 17-1 11 17-1 1 1 1 9 1 8-1 7-1 10 5-2 1 1 1 2 7-1 5-2 1 1 1 14 15 13 7-1 10 5-2 14 1 1 1 13 4-2 1 8-2 8-2 18-1 1 1 1 7-1 14 1 1 1 1 1 1 1 2 16-1 9 9 4-2 13 1 1 1 2 16-1 15 1 1 1 11 6 1 1 1 17-1 4-2 8-2 8-2 1 1 1 7-1 1 1 1 5-2 16-1 4-2 14 14 1 1 1
```

We have the first number going from 1 to 18, and the second being either absent, 1, or 2.
We can then match the first number being the "row" on the register, and the second number being the letter "offset" on that row  (or the letter itself when absent).

```
python tallon.py

IDEKAAAMAKINGAAABIGAAAFLAGSAAAJUSTAAATOAAAMAKEAAAYOUAAAUSEAAAAAAASCRIPTAAAORAAABEAAAANNOYEDAAAATAAAMEAAAEHEHEHAAAWOWAAAMAKINGAAABIGAAASTRINGSAAAREALLYAAAISAAAAAAABUMMERAAABUTAAAOHAAAWELLAAAIAAAGUESSAAA
```