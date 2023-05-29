for i in {2..10}
do
	cp good_boy$(($i - 1)).jpg good_boy$i.jpg
	echo "Created good_boy$i.jpg from $(($i - 1))"
done
