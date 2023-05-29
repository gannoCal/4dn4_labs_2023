for i in {2..10}
do
	cp pizza$(($i - 1)).jpg pizza$i.jpg
	echo "Created pizza$i.jpg from $(($i - 1))"
done
