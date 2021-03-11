import 'package:flutter/material.dart';
import 'package:http/http.dart';

void main() => runApp(SSLPlayground());

/// This is the main application widget.
class SSLPlayground extends StatelessWidget {
  static const String _title = 'Flutter Code Sample';

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: _title,
      home: MyStatefulWidget(),
    );
  }
}

/// This is the stateful widget that the main application instantiates.
class MyStatefulWidget extends StatefulWidget {
  @override
  _MyStatefulWidgetState createState() => _MyStatefulWidgetState();
}

/// This is the private State class that goes with MyStatefulWidget.
class _MyStatefulWidgetState extends State<MyStatefulWidget> {
  Widget text = Center(child: Text('Press the button to GET google.com'));

  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Sample Code'),
      ),
      body: text,
      floatingActionButton: FloatingActionButton(
        onPressed: getGoogle,
        tooltip: 'GET google.com',
        child: const Icon(Icons.cloud_download),
      ),
    );
  }

  Future<void> getGoogle() async {
    try {
      Response res = await get("https://www.google.com");
      if (res.statusCode != 200) {
        setState(() {
          text = Center(child: Text('HTTP Error ${res.statusCode}'));
        });
      } else {
        setState(() {
          text = Center(
            child: Container(
              // adding margin

              margin: const EdgeInsets.all(15.0),
              // adding padding

              padding: const EdgeInsets.all(3.0),
              decoration: BoxDecoration(
                // adding borders around the widget
                border: Border.all(
                  width: 1.0,
                ),
              ),
              child: SingleChildScrollView(
                scrollDirection: Axis.vertical,
                child: Text(res.body),
              ),
            ),
          );
        });
      }
    } catch (e) {
      setState(() {
        text = Center(child: Text('Failed to look up url'));
      });
      return;
    }
  }
}
